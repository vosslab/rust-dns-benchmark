use anyhow::{anyhow, Result};
use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

use crate::transport::QueryType;

/// DNS response information extracted from a parsed message
#[derive(Debug)]
#[allow(dead_code)]
pub struct DnsResponse {
	pub rcode: ResponseCode,
	pub rcode_str: String,
	pub answer_count: usize,
}

/// Build a DNS query message for the given domain and query type.
///
/// Returns the serialized query bytes ready to send over UDP.
pub fn build_query(domain: &str, query_type: QueryType, txid: u16) -> Result<Vec<u8>> {
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

	Ok(DnsResponse {
		rcode,
		rcode_str,
		answer_count,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_build_a_query() {
		let result = build_query("example.com", QueryType::A, 1234);
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
		let result = build_query("example.com", QueryType::AAAA, 5678);
		assert!(result.is_ok());
		let bytes = result.unwrap();
		assert!(bytes.len() >= 12);
		// Verify txid
		assert_eq!(bytes[0], (5678 >> 8) as u8);
		assert_eq!(bytes[1], (5678 & 0xff) as u8);
	}

	#[test]
	fn test_parse_valid_response() {
		// Build a query, then turn it into a response
		let query_bytes = build_query("example.com", QueryType::A, 9999).unwrap();
		let mut response = Message::from_vec(&query_bytes).unwrap();
		response.set_message_type(MessageType::Response);
		let response_bytes = response.to_vec().unwrap();

		let result = parse_response(&response_bytes, 9999, "example.com", QueryType::A);
		assert!(result.is_ok());
		let dns_resp = result.unwrap();
		assert_eq!(dns_resp.rcode, ResponseCode::NoError);
	}

	#[test]
	fn test_txid_mismatch() {
		let query_bytes = build_query("example.com", QueryType::A, 1111).unwrap();
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
