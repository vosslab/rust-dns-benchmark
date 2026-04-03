use std::net::SocketAddr;

use anyhow::{anyhow, Result};

use crate::transport::{DnsTransport, ResolverConfig};

/// Parse a resolver address string into a ResolverConfig.
///
/// Supports formats:
///   "1.1.1.1"                           -- UDP, default port 53
///   "1.1.1.1:53"                        -- UDP with explicit port
///   "2606:4700::1111"                   -- UDP, bare IPv6, default port 53
///   "[2606:4700::1111]:53"              -- UDP, bracketed IPv6 with port
///   "tls://1.1.1.1"                     -- DoT, default port 853
///   "tls://1.1.1.1:853"                -- DoT with explicit port
///   "tls://dns.google/8.8.8.8"         -- DoT with SNI hostname
///   "https://1.1.1.1/dns-query"        -- DoH
///   "https://dns.google/dns-query"     -- DoH with hostname
pub fn parse_resolver(input: &str) -> Result<ResolverConfig> {
	let trimmed = input.trim();
	if trimmed.is_empty() {
		return Err(anyhow!("empty resolver address"));
	}

	// Detect transport scheme
	if trimmed.starts_with("https://") {
		return parse_doh_resolver(trimmed);
	}
	if trimmed.starts_with("tls://") {
		return parse_dot_resolver(trimmed);
	}

	// Plain UDP resolver
	let addr = parse_socket_addr(trimmed, 53)?;
	let label = format!("{}", addr.ip());
	Ok(ResolverConfig {
		label, addr,
		transport: DnsTransport::Udp,
		intercepts_nxdomain: false, is_system: false,
		ptr_name: None, rebinding_protection: None, validates_dnssec: None,
	})
}

/// Parse a DoH resolver URL like "https://1.1.1.1/dns-query"
fn parse_doh_resolver(url: &str) -> Result<ResolverConfig> {
	// Strip scheme to extract host and path
	let after_scheme = &url["https://".len()..];

	// Extract host portion (before first '/')
	let (host_port, _path) = match after_scheme.find('/') {
		Some(i) => (&after_scheme[..i], &after_scheme[i..]),
		None => (after_scheme, "/dns-query"),
	};

	// Parse the host as an IP address for the addr field
	let addr = parse_host_to_addr(host_port, 443)?;
	let label = host_port.to_string();

	Ok(ResolverConfig {
		label, addr,
		transport: DnsTransport::Doh { url: url.to_string() },
		intercepts_nxdomain: false, is_system: false,
		ptr_name: None, rebinding_protection: None, validates_dnssec: None,
	})
}

/// Parse a DoT resolver like "tls://1.1.1.1" or "tls://dns.google/8.8.8.8"
fn parse_dot_resolver(input: &str) -> Result<ResolverConfig> {
	let after_scheme = &input["tls://".len()..];

	// Check for "hostname/IP" format for SNI + IP separation
	let (hostname, addr) = if let Some(slash_idx) = after_scheme.find('/') {
		let hostname = &after_scheme[..slash_idx];
		let ip_part = &after_scheme[slash_idx + 1..];
		let addr = parse_socket_addr(ip_part, 853)?;
		(hostname.to_string(), addr)
	} else {
		// Just an IP address, use IP as both addr and hostname
		let addr = parse_socket_addr(after_scheme, 853)?;
		let hostname = after_scheme.split(':').next().unwrap_or(after_scheme);
		(hostname.to_string(), addr)
	};

	let label = hostname.clone();
	Ok(ResolverConfig {
		label, addr,
		transport: DnsTransport::Dot { hostname },
		intercepts_nxdomain: false, is_system: false,
		ptr_name: None, rebinding_protection: None, validates_dnssec: None,
	})
}

/// Parse a host:port string to a SocketAddr, supporting IPv4, IPv6, and hostnames.
///
/// For hostnames that cannot be parsed as IPs, attempts DNS resolution.
fn parse_host_to_addr(host_port: &str, default_port: u16) -> Result<SocketAddr> {
	// Handle bracketed IPv6: [::1]:443
	if host_port.starts_with('[') {
		let addr: SocketAddr = host_port.parse()
			.map_err(|e| anyhow!("invalid bracketed address '{}': {}", host_port, e))?;
		return Ok(addr);
	}

	// Try as IP:port or plain IP
	if let Ok(addr) = host_port.parse::<SocketAddr>() {
		return Ok(addr);
	}
	if let Ok(ip) = host_port.parse::<std::net::IpAddr>() {
		return Ok(SocketAddr::new(ip, default_port));
	}

	// Split off port if present (hostname:port)
	let (host, port) = if let Some(colon_idx) = host_port.rfind(':') {
		let port_str = &host_port[colon_idx + 1..];
		if let Ok(port) = port_str.parse::<u16>() {
			(&host_port[..colon_idx], port)
		} else {
			(host_port, default_port)
		}
	} else {
		(host_port, default_port)
	};

	// Try DNS resolution for hostnames
	use std::net::ToSocketAddrs;
	let addr_str = format!("{}:{}", host, port);
	let addr = addr_str.to_socket_addrs()
		.map_err(|e| anyhow!("cannot resolve hostname '{}': {}", host, e))?
		.next()
		.ok_or_else(|| anyhow!("no addresses found for hostname '{}'", host))?;
	Ok(addr)
}

/// Parse a plain socket address string with a default port.
fn parse_socket_addr(input: &str, default_port: u16) -> Result<SocketAddr> {
	let trimmed = input.trim();

	if trimmed.starts_with('[') {
		// Bracketed IPv6 with port: [::1]:53
		let addr: SocketAddr = trimmed.parse()
			.map_err(|e| anyhow!("invalid bracketed IPv6 address '{}': {}", trimmed, e))?;
		Ok(addr)
	} else if trimmed.contains("::") || trimmed.matches(':').count() > 1 {
		// Bare IPv6 address without port
		let ip = trimmed.parse()
			.map_err(|e| anyhow!("invalid IPv6 address '{}': {}", trimmed, e))?;
		Ok(SocketAddr::new(ip, default_port))
	} else if let Ok(addr) = trimmed.parse::<SocketAddr>() {
		// IPv4 with port
		Ok(addr)
	} else {
		// Plain IPv4 without port
		let ip = trimmed.parse()
			.map_err(|e| anyhow!("invalid IP address '{}': {}", trimmed, e))?;
		Ok(SocketAddr::new(ip, default_port))
	}
}

/// Parse a resolver line that may contain an inline comment label.
///
/// Format: "IP_ADDRESS  # Label" or "https://url  # Label"
/// The label after '#' becomes the resolver's display name.
fn parse_resolver_line(line: &str) -> Result<ResolverConfig> {
	let trimmed = line.trim();

	// Split address and label, handling scheme-prefixed URLs
	let (addr_part, label_part) = split_addr_label(trimmed);

	let mut config = parse_resolver(addr_part)?;

	// Use the inline comment as the label if present
	if let Some(label) = label_part {
		if !label.is_empty() {
			config.label = label.to_string();
		}
	}

	Ok(config)
}

/// Parse a resolver line, detecting transport scheme before splitting label.
///
/// For DoH/DoT URLs, the '#' inside URLs must not be treated as a comment
/// delimiter, so we handle scheme-prefixed lines specially.
fn split_addr_label(line: &str) -> (&str, Option<&str>) {
	let trimmed = line.trim();

	// For scheme-prefixed URLs, find '#' that comes after the URL
	if trimmed.starts_with("https://") || trimmed.starts_with("tls://") {
		// Find the first '#' that has whitespace before it (indicating a comment)
		if let Some(idx) = trimmed.find(" #").or_else(|| trimmed.find("\t#")) {
			let addr = trimmed[..idx].trim();
			let label = trimmed[idx + 2..].trim();
			return (addr, Some(label));
		}
		return (trimmed, None);
	}

	// Plain address: split on first '#'
	if let Some(idx) = trimmed.find('#') {
		let addr = trimmed[..idx].trim();
		let label = trimmed[idx + 1..].trim();
		(addr, Some(label))
	} else {
		(trimmed, None)
	}
}

/// Read resolver addresses from a file, one per line.
///
/// Blank lines and lines starting with '#' are skipped.
/// Inline comments after the address (e.g. "1.1.1.1 # Cloudflare") set the label.
pub fn read_resolver_file(path: &str) -> Result<Vec<ResolverConfig>> {
	let content = std::fs::read_to_string(path)
		.map_err(|e| anyhow!("failed to read resolver file '{}': {}", path, e))?;
	let mut resolvers = Vec::new();
	for line in content.lines() {
		let trimmed = line.trim();
		// Skip blank lines and full-line comments
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		resolvers.push(parse_resolver_line(trimmed)?);
	}
	Ok(resolvers)
}

/// Read system resolvers from /etc/resolv.conf (Unix only).
///
/// Returns an empty vec on non-Unix platforms or if the file cannot be read.
pub fn system_resolvers() -> Vec<ResolverConfig> {
	let content = match std::fs::read_to_string("/etc/resolv.conf") {
		Ok(c) => c,
		Err(_) => return Vec::new(),
	};
	let mut resolvers = Vec::new();
	for line in content.lines() {
		let trimmed = line.trim();
		if !trimmed.starts_with("nameserver") {
			continue;
		}
		// Extract the address after "nameserver"
		let parts: Vec<&str> = trimmed.split_whitespace().collect();
		if parts.len() >= 2 {
			if let Ok(mut resolver) = parse_resolver(parts[1]) {
				resolver.is_system = true;
				// System resolvers are always UDP
				resolver.transport = DnsTransport::Udp;
				resolvers.push(resolver);
			}
		}
	}
	resolvers
}

/// Try to find a resolver file by name in resolvers/ dir, CWD, or exe dir.
fn find_resolver_file(filename: &str) -> Option<Vec<ResolverConfig>> {
	// Look in resolvers/ subdir first, then CWD, then next to the executable
	let candidates = vec![
		std::path::PathBuf::from("resolvers").join(filename),
		std::path::PathBuf::from(filename),
		std::env::current_exe()
			.ok()
			.and_then(|p| p.parent().map(|d| d.join("resolvers").join(filename)))
			.unwrap_or_default(),
		std::env::current_exe()
			.ok()
			.and_then(|p| p.parent().map(|d| d.join(filename)))
			.unwrap_or_default(),
	];
	for path in &candidates {
		if path.exists() {
			if let Ok(resolvers) = read_resolver_file(
				path.to_str().unwrap_or(filename),
			) {
				if !resolvers.is_empty() {
					return Some(resolvers);
				}
			}
		}
	}
	None
}

/// Return a list of well-known default resolvers (IPv4 UDP only).
///
/// Reads from the bundled resolvers.txt at the repo root. Falls back to
/// a minimal hardcoded list if the file cannot be found.
pub fn default_resolvers() -> Vec<ResolverConfig> {
	if let Some(resolvers) = find_resolver_file("resolvers.txt") {
		return resolvers;
	}

	// Hardcoded fallback if resolvers.txt is not found
	vec![
		ResolverConfig {
			label: "Cloudflare".to_string(),
			addr: "1.1.1.1:53".parse().unwrap(),
			transport: DnsTransport::Udp,
			intercepts_nxdomain: false, is_system: false,
			ptr_name: None, rebinding_protection: None, validates_dnssec: None,
		},
		ResolverConfig {
			label: "Google".to_string(),
			addr: "8.8.8.8:53".parse().unwrap(),
			transport: DnsTransport::Udp,
			intercepts_nxdomain: false, is_system: false,
			ptr_name: None, rebinding_protection: None, validates_dnssec: None,
		},
		ResolverConfig {
			label: "Quad9".to_string(),
			addr: "9.9.9.9:53".parse().unwrap(),
			transport: DnsTransport::Udp,
			intercepts_nxdomain: false, is_system: false,
			ptr_name: None, rebinding_protection: None, validates_dnssec: None,
		},
		ResolverConfig {
			label: "OpenDNS".to_string(),
			addr: "208.67.222.222:53".parse().unwrap(),
			transport: DnsTransport::Udp,
			intercepts_nxdomain: false, is_system: false,
			ptr_name: None, rebinding_protection: None, validates_dnssec: None,
		},
	]
}

/// Return built-in IPv6 resolvers from resolvers_ipv6.txt.
pub fn default_ipv6_resolvers() -> Vec<ResolverConfig> {
	find_resolver_file("resolvers_ipv6.txt").unwrap_or_default()
}

/// Return built-in DoH resolvers from resolvers_doh.txt.
pub fn default_doh_resolvers() -> Vec<ResolverConfig> {
	find_resolver_file("resolvers_doh.txt").unwrap_or_default()
}

/// Return built-in DoT resolvers from resolvers_dot.txt.
pub fn default_dot_resolvers() -> Vec<ResolverConfig> {
	find_resolver_file("resolvers_dot.txt").unwrap_or_default()
}

/// Return the large scan list from scan_us.txt (~11K US public resolvers).
pub fn scan_resolvers() -> Vec<ResolverConfig> {
	find_resolver_file("scan_us.txt").unwrap_or_default()
}

/// Return the global scan list from scan_global.txt (~63K worldwide public resolvers).
pub fn scan_global_resolvers() -> Vec<ResolverConfig> {
	find_resolver_file("scan_global.txt").unwrap_or_default()
}

/// Download the global nameserver list from public-dns.info to resolvers/scan_global.txt.
/// Returns the path to the downloaded file.
pub async fn download_global_list() -> Result<String> {
	let url = "https://public-dns.info/nameservers.txt";
	let response = reqwest::get(url).await
		.map_err(|e| anyhow!("Failed to download nameserver list: {}", e))?;
	let body = response.text().await
		.map_err(|e| anyhow!("Failed to read nameserver list response: {}", e))?;

	// Write to resolvers/ directory if it exists, otherwise current directory
	let path = if std::path::Path::new("resolvers").is_dir() {
		"resolvers/scan_global.txt".to_string()
	} else {
		"scan_global.txt".to_string()
	};
	std::fs::write(&path, &body)
		.map_err(|e| anyhow!("Failed to write {}: {}", path, e))?;

	let line_count = body.lines().filter(|l| !l.trim().is_empty()).count();
	println!("  Downloaded {} nameservers to {}", line_count, path);
	Ok(path)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ipv4_no_port() {
		let r = parse_resolver("1.1.1.1").unwrap();
		assert_eq!(r.addr.port(), 53);
		assert_eq!(r.addr.ip().to_string(), "1.1.1.1");
	}

	#[test]
	fn test_ipv4_with_port() {
		let r = parse_resolver("8.8.8.8:5353").unwrap();
		assert_eq!(r.addr.port(), 5353);
		assert_eq!(r.addr.ip().to_string(), "8.8.8.8");
	}

	#[test]
	fn test_ipv6_bare() {
		let r = parse_resolver("2606:4700::1111").unwrap();
		assert_eq!(r.addr.port(), 53);
	}

	#[test]
	fn test_ipv6_bracketed() {
		let r = parse_resolver("[2606:4700::1111]:53").unwrap();
		assert_eq!(r.addr.port(), 53);
	}

	#[test]
	fn test_invalid_input() {
		let r = parse_resolver("not-an-ip");
		assert!(r.is_err());
	}

	#[test]
	fn test_defaults_non_empty() {
		let defaults = default_resolvers();
		assert!(!defaults.is_empty());
		// Should load from resolvers.txt (50+) or fallback to 4
		assert!(defaults.len() >= 4);
	}

	#[test]
	fn test_parse_resolver_line_with_label() {
		let r = parse_resolver_line("1.1.1.1  # Cloudflare").unwrap();
		assert_eq!(r.label, "Cloudflare");
		assert_eq!(r.addr.ip().to_string(), "1.1.1.1");
		assert_eq!(r.addr.port(), 53);
	}

	#[test]
	fn test_parse_resolver_line_without_label() {
		let r = parse_resolver_line("8.8.8.8").unwrap();
		assert_eq!(r.label, "8.8.8.8");
		assert_eq!(r.addr.ip().to_string(), "8.8.8.8");
	}

	#[test]
	fn test_doh_resolver() {
		let r = parse_resolver("https://1.1.1.1/dns-query").unwrap();
		assert_eq!(r.addr.port(), 443);
		assert_eq!(r.addr.ip().to_string(), "1.1.1.1");
		assert!(matches!(r.transport, DnsTransport::Doh { .. }));
	}

	#[test]
	fn test_dot_resolver() {
		let r = parse_resolver("tls://1.1.1.1").unwrap();
		assert_eq!(r.addr.port(), 853);
		assert_eq!(r.addr.ip().to_string(), "1.1.1.1");
		assert!(matches!(r.transport, DnsTransport::Dot { .. }));
	}

	#[test]
	fn test_dot_resolver_with_port() {
		let r = parse_resolver("tls://9.9.9.9:8853").unwrap();
		assert_eq!(r.addr.port(), 8853);
		assert_eq!(r.addr.ip().to_string(), "9.9.9.9");
	}

	#[test]
	fn test_doh_with_label() {
		let r = parse_resolver_line("https://1.1.1.1/dns-query  # Cloudflare DoH").unwrap();
		assert_eq!(r.label, "Cloudflare DoH");
		assert!(matches!(r.transport, DnsTransport::Doh { .. }));
	}

	#[test]
	fn test_udp_transport_default() {
		let r = parse_resolver("8.8.8.8").unwrap();
		assert!(matches!(r.transport, DnsTransport::Udp));
	}
}
