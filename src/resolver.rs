use std::net::SocketAddr;

use anyhow::{anyhow, Result};

use crate::transport::ResolverConfig;

/// Parse a resolver address string into a ResolverConfig.
///
/// Supports formats:
///   "1.1.1.1"              -- IPv4, default port 53
///   "1.1.1.1:53"           -- IPv4 with explicit port
///   "2606:4700::1111"      -- bare IPv6, default port 53
///   "[2606:4700::1111]:53" -- bracketed IPv6 with port
pub fn parse_resolver(input: &str) -> Result<ResolverConfig> {
	let trimmed = input.trim();
	if trimmed.is_empty() {
		return Err(anyhow!("empty resolver address"));
	}

	let addr: SocketAddr = if trimmed.starts_with('[') {
		// Bracketed IPv6 with port: [::1]:53
		trimmed.parse()
			.map_err(|e| anyhow!("invalid bracketed IPv6 address '{}': {}", trimmed, e))?
	} else if trimmed.contains("::") || trimmed.matches(':').count() > 1 {
		// Bare IPv6 address without port
		let ip = trimmed.parse()
			.map_err(|e| anyhow!("invalid IPv6 address '{}': {}", trimmed, e))?;
		SocketAddr::new(ip, 53)
	} else if let Ok(addr) = trimmed.parse::<SocketAddr>() {
		// IPv4 with port (e.g. "8.8.8.8:5353")
		addr
	} else {
		// Plain IPv4 without port
		let ip = trimmed.parse()
			.map_err(|e| anyhow!("invalid IP address '{}': {}", trimmed, e))?;
		SocketAddr::new(ip, 53)
	};

	let label = format!("{}", addr.ip());
	Ok(ResolverConfig { label, addr })
}

/// Read resolver addresses from a file, one per line.
///
/// Blank lines and lines starting with '#' are skipped.
pub fn read_resolver_file(path: &str) -> Result<Vec<ResolverConfig>> {
	let content = std::fs::read_to_string(path)
		.map_err(|e| anyhow!("failed to read resolver file '{}': {}", path, e))?;
	let mut resolvers = Vec::new();
	for line in content.lines() {
		let trimmed = line.trim();
		if trimmed.is_empty() || trimmed.starts_with('#') {
			continue;
		}
		resolvers.push(parse_resolver(trimmed)?);
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
			if let Ok(resolver) = parse_resolver(parts[1]) {
				resolvers.push(resolver);
			}
		}
	}
	resolvers
}

/// Return a list of well-known default resolvers.
pub fn default_resolvers() -> Vec<ResolverConfig> {
	vec![
		ResolverConfig {
			label: "Cloudflare".to_string(),
			addr: "1.1.1.1:53".parse().unwrap(),
		},
		ResolverConfig {
			label: "Google".to_string(),
			addr: "8.8.8.8:53".parse().unwrap(),
		},
		ResolverConfig {
			label: "Quad9".to_string(),
			addr: "9.9.9.9:53".parse().unwrap(),
		},
		ResolverConfig {
			label: "OpenDNS".to_string(),
			addr: "208.67.222.222:53".parse().unwrap(),
		},
	]
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
		assert_eq!(defaults.len(), 4);
	}
}
