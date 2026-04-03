use std::time::Duration;

use anyhow::{anyhow, Result};
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::net::UdpSocket;

use crate::transport::QueryType;

/// DNS response information extracted from a parsed message
#[derive(Debug)]
pub struct DnsResponse {
	pub rcode: ResponseCode,
	pub rcode_str: String,
	#[allow(dead_code)]
	pub answer_count: usize,
	/// True if the answer section contains A records
	pub has_a_records: bool,
}

/// Build a DNS query message for the given domain and query type.
///
/// When dnssec is true, the DO (DNSSEC OK) bit is set via EDNS.
/// Returns the serialized query bytes ready to send over UDP.
pub fn build_query(
	domain: &str,
	query_type: QueryType,
	txid: u16,
	dnssec: bool,
) -> Result<Vec<u8>> {
	let name = Name::from_ascii(domain)
		.map_err(|e| anyhow!("invalid domain name '{}': {}", domain, e))?;

	let record_type = match query_type {
		QueryType::A => RecordType::A,
		QueryType::AAAA => RecordType::AAAA,
	};

	let mut message = Message::new();
	message.set_id(txid);
	message.set_recursion_desired(true);
	message.add_query(Query::query(name, record_type));

	// Set DNSSEC OK bit via EDNS when requested
	if dnssec {
		let edns = message.extensions_mut()
			.get_or_insert_with(hickory_proto::op::Edns::new);
		edns.set_dnssec_ok(true);
	}

	let bytes = message.to_vec()
		.map_err(|e| anyhow!("failed to serialize DNS query: {}", e))?;
	Ok(bytes)
}

/// Parse a DNS response, validating the transaction ID and extracting the rcode.
///
/// Returns an error if the response cannot be parsed or the txid does not match.
pub fn parse_response(
	bytes: &[u8],
	expected_txid: u16,
	_expected_domain: &str,
	_expected_type: QueryType,
) -> Result<DnsResponse> {
	let message = Message::from_vec(bytes)
		.map_err(|e| anyhow!("failed to parse DNS response: {}", e))?;

	// Validate transaction ID
	if message.id() != expected_txid {
		return Err(anyhow!(
			"txid mismatch: expected {}, got {}",
			expected_txid, message.id()
		));
	}

	// Verify this is a response, not a query
	if message.message_type() != MessageType::Response {
		return Err(anyhow!("received a query instead of a response"));
	}

	let rcode = message.response_code();
	let rcode_str = format!("{}", rcode);
	let answer_count = message.answer_count() as usize;

	// Check if any answer records are A records
	let has_a_records = message.answers().iter()
		.any(|r| r.record_type() == RecordType::A);

	Ok(DnsResponse {
		rcode,
		rcode_str,
		answer_count,
		has_a_records,
	})
}

/// Build a DNS PTR query for reverse DNS lookups.
pub fn build_ptr_query(ptr_domain: &str, txid: u16) -> Result<Vec<u8>> {
	let name = Name::from_ascii(ptr_domain)
		.map_err(|e| anyhow!("invalid PTR domain '{}': {}", ptr_domain, e))?;

	let mut message = Message::new();
	message.set_id(txid);
	message.set_recursion_desired(true);
	message.add_query(Query::query(name, RecordType::PTR));

	let bytes = message.to_vec()
		.map_err(|e| anyhow!("failed to serialize PTR query: {}", e))?;
	Ok(bytes)
}

/// Parse a PTR response and extract the hostname.
///
/// Returns the first PTR record's hostname, or None if no PTR records found.
pub fn parse_ptr_response(bytes: &[u8], expected_txid: u16) -> Option<String> {
	let message = Message::from_vec(bytes).ok()?;
	if message.id() != expected_txid {
		return None;
	}
	if message.message_type() != MessageType::Response {
		return None;
	}

	// Find the first PTR record in the answer section
	for record in message.answers() {
		if record.record_type() == RecordType::PTR {
			let rdata = record.data();
			// Extract the PTR hostname string
			let ptr_str = format!("{}", rdata);
			// Remove trailing dot if present
			let hostname = ptr_str.trim_end_matches('.').to_string();
			return Some(hostname);
		}
	}
	None
}

/// Check whether a resolver has DNS rebinding protection.
///
/// Queries domains known to resolve to private/loopback IP addresses.
/// If the resolver blocks or filters these responses, it has rebinding protection.
/// We query known rebinding test domains and check if the response is filtered.
pub async fn check_rebinding_protection(
	resolver_addr: std::net::SocketAddr,
	timeout: Duration,
) -> Option<bool> {
	// Test domains that resolve to loopback/private IPs
	// These are well-known rebinding test domains
	let test_domains = [
		"localhost",           // Should resolve to 127.0.0.1
	];

	for domain in &test_domains {
		let txid: u16 = rand::random();
		let query_bytes = match build_query(domain, QueryType::A, txid, false) {
			Ok(b) => b,
			Err(_) => continue,
		};

		let bind_addr = if resolver_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
		let socket = match UdpSocket::bind(bind_addr).await {
			Ok(s) => s,
			Err(_) => continue,
		};

		if socket.send_to(&query_bytes, resolver_addr).await.is_err() {
			continue;
		}

		let mut buf = vec![0u8; 4096];
		match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
			Ok(Ok((len, _))) => {
				let message = match Message::from_vec(&buf[..len]) {
					Ok(m) => m,
					Err(_) => continue,
				};
				if message.id() != txid { continue; }

				// Check if any A records contain private/loopback IPs
				let has_private_ip = message.answers().iter().any(|r| {
					if r.record_type() == RecordType::A {
						let rdata_str = format!("{}", r.data());
						return is_private_ip(&rdata_str);
					}
					false
				});

				if has_private_ip {
					// Resolver returned private IPs -- no rebinding protection
					return Some(false);
				}

				// If we got a response but no private IPs, check if it was filtered
				if message.response_code() == ResponseCode::NoError
					&& message.answer_count() == 0 {
					// Response filtered -- has rebinding protection
					return Some(true);
				}
				if message.response_code() == ResponseCode::Refused
					|| message.response_code() == ResponseCode::NXDomain {
					// Resolver refused or said NXDOMAIN -- has rebinding protection
					return Some(true);
				}
			}
			_ => continue,
		}
	}
	// Could not determine
	None
}

/// Check if an IP address string is a private/loopback address.
fn is_private_ip(ip_str: &str) -> bool {
	if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
		// Loopback: 127.0.0.0/8
		if ip.octets()[0] == 127 { return true; }
		// Private: 10.0.0.0/8
		if ip.octets()[0] == 10 { return true; }
		// Private: 172.16.0.0/12
		if ip.octets()[0] == 172 && (ip.octets()[1] >= 16 && ip.octets()[1] <= 31) {
			return true;
		}
		// Private: 192.168.0.0/16
		if ip.octets()[0] == 192 && ip.octets()[1] == 168 { return true; }
	}
	false
}

/// Check whether a resolver validates DNSSEC signatures.
///
/// Queries `dnssec-failed.org`, a domain with intentionally broken DNSSEC.
/// A validating resolver should return SERVFAIL for this domain.
/// A non-validating resolver returns the answer normally.
pub async fn check_dnssec_validation(
	resolver_addr: std::net::SocketAddr,
	timeout: Duration,
) -> Option<bool> {
	// dnssec-failed.org has intentionally broken DNSSEC signatures
	let test_domain = "dnssec-failed.org";
	let txid: u16 = rand::random();

	// Query with DNSSEC DO bit set
	let query_bytes = match build_query(test_domain, QueryType::A, txid, true) {
		Ok(b) => b,
		Err(_) => return None,
	};

	let bind_addr = if resolver_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
	let socket = match UdpSocket::bind(bind_addr).await {
		Ok(s) => s,
		Err(_) => return None,
	};

	if socket.send_to(&query_bytes, resolver_addr).await.is_err() {
		return None;
	}

	let mut buf = vec![0u8; 4096];
	match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
		Ok(Ok((len, _))) => {
			let message = match Message::from_vec(&buf[..len]) {
				Ok(m) => m,
				Err(_) => return None,
			};
			if message.id() != txid { return None; }

			// SERVFAIL for broken DNSSEC = resolver validates
			if message.response_code() == ResponseCode::ServFail {
				return Some(true);
			}
			// NoError = resolver does NOT validate DNSSEC
			if message.response_code() == ResponseCode::NoError {
				return Some(false);
			}
			None
		}
		_ => None,
	}
}

/// Check whether a resolver intercepts NXDOMAIN responses.
///
/// Queries a known-nonexistent domain (.invalid TLD per RFC 2606).
/// If the resolver returns NoError with A records, it is intercepting.
/// Returns true if the resolver intercepts NXDOMAIN, false if honest.
pub async fn check_nxdomain_interception(
	resolver_addr: std::net::SocketAddr,
	timeout: Duration,
	nxdomain_domains: &[String],
) -> bool {
	// Query each NXDOMAIN probe domain; if any returns NoError with A records,
	// the resolver is intercepting
	for probe_domain in nxdomain_domains {
		if check_single_nxdomain(resolver_addr, timeout, probe_domain).await {
			return true;
		}
	}
	false
}

/// Check a single NXDOMAIN probe domain against a resolver.
///
/// Returns true if the resolver intercepts (returns NoError + A records).
async fn check_single_nxdomain(
	resolver_addr: std::net::SocketAddr,
	timeout: Duration,
	probe_domain: &str,
) -> bool {
	let txid: u16 = rand::random();

	let query_bytes = match build_query(probe_domain, QueryType::A, txid, false) {
		Ok(bytes) => bytes,
		Err(_) => return false,
	};

	// Bind a dedicated socket
	let bind_addr = if resolver_addr.is_ipv4() {
		"0.0.0.0:0"
	} else {
		"[::]:0"
	};
	let socket = match UdpSocket::bind(bind_addr).await {
		Ok(s) => s,
		Err(_) => return false,
	};

	// Send query
	if socket.send_to(&query_bytes, resolver_addr).await.is_err() {
		return false;
	}

	// Receive response with timeout
	let mut buf = vec![0u8; 512];
	match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
		Ok(Ok((len, _src))) => {
			match parse_response(&buf[..len], txid, probe_domain, QueryType::A) {
				Ok(response) => {
					// Intercepting: NoError with A records for a nonexistent domain
					response.rcode == ResponseCode::NoError && response.has_a_records
				}
				Err(_) => false,
			}
		}
		_ => false,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_build_a_query() {
		let result = build_query("example.com", QueryType::A, 1234, false);
		assert!(result.is_ok());
		let bytes = result.unwrap();
		// DNS header is 12 bytes minimum
		assert!(bytes.len() >= 12);
		// Verify txid in first two bytes (big-endian)
		assert_eq!(bytes[0], (1234 >> 8) as u8);
		assert_eq!(bytes[1], (1234 & 0xff) as u8);
	}

	#[test]
	fn test_build_aaaa_query() {
		let result = build_query("example.com", QueryType::AAAA, 5678, false);
		assert!(result.is_ok());
		let bytes = result.unwrap();
		assert!(bytes.len() >= 12);
		// Verify txid
		assert_eq!(bytes[0], (5678 >> 8) as u8);
		assert_eq!(bytes[1], (5678 & 0xff) as u8);
	}

	#[test]
	fn test_build_dnssec_query() {
		let result = build_query("example.com", QueryType::A, 4321, true);
		assert!(result.is_ok());
		let bytes = result.unwrap();
		// DNSSEC queries include EDNS OPT record, so they are larger
		// than a plain query (which is typically ~29 bytes for example.com)
		let plain = build_query("example.com", QueryType::A, 4321, false).unwrap();
		assert!(bytes.len() > plain.len(), "DNSSEC query should be larger than plain query");
		// Parse back to verify EDNS is present
		let message = Message::from_vec(&bytes).unwrap();
		assert!(message.extensions().is_some(), "EDNS extension should be present");
	}

	#[test]
	fn test_parse_valid_response() {
		// Build a query, then turn it into a response
		let query_bytes = build_query("example.com", QueryType::A, 9999, false).unwrap();
		let mut response = Message::from_vec(&query_bytes).unwrap();
		response.set_message_type(MessageType::Response);
		let response_bytes = response.to_vec().unwrap();

		let result = parse_response(&response_bytes, 9999, "example.com", QueryType::A);
		assert!(result.is_ok());
		let dns_resp = result.unwrap();
		assert_eq!(dns_resp.rcode, ResponseCode::NoError);
		assert!(!dns_resp.has_a_records);
	}

	#[test]
	fn test_txid_mismatch() {
		let query_bytes = build_query("example.com", QueryType::A, 1111, false).unwrap();
		let mut response = Message::from_vec(&query_bytes).unwrap();
		response.set_message_type(MessageType::Response);
		let response_bytes = response.to_vec().unwrap();

		// Parse with wrong expected txid
		let result = parse_response(&response_bytes, 2222, "example.com", QueryType::A);
		assert!(result.is_err());
		assert!(result.unwrap_err().to_string().contains("txid mismatch"));
	}

	#[test]
	fn test_truncated_buffer() {
		// Only 5 bytes -- too short for a valid DNS message
		let bytes = vec![0u8; 5];
		let result = parse_response(&bytes, 0, "example.com", QueryType::A);
		assert!(result.is_err());
	}
}
