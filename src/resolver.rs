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
	Ok(ResolverConfig { label, addr, intercepts_nxdomain: false })
}

/// Parse a resolver line that may contain an inline comment label.
///
/// Format: "IP_ADDRESS  # Label"
/// The label after '#' becomes the resolver's display name.
fn parse_resolver_line(line: &str) -> Result<ResolverConfig> {
	let trimmed = line.trim();

	// Split on '#' to extract optional label
	let (addr_part, label_part) = if let Some(idx) = trimmed.find('#') {
		let addr = trimmed[..idx].trim();
		let label = trimmed[idx + 1..].trim();
		(addr, Some(label))
	} else {
		(trimmed, None)
	};

	let mut config = parse_resolver(addr_part)?;

	// Use the inline comment as the label if present
	if let Some(label) = label_part {
		if !label.is_empty() {
			config.label = label.to_string();
		}
	}

	Ok(config)
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
			if let Ok(resolver) = parse_resolver(parts[1]) {
				resolvers.push(resolver);
			}
		}
	}
	resolvers
}

/// Return a list of well-known default resolvers.
///
/// Reads from the bundled resolvers.txt at the repo root. Falls back to
/// a minimal hardcoded list if the file cannot be found.
pub fn default_resolvers() -> Vec<ResolverConfig> {
	// Try to find resolvers.txt relative to the executable or repo root
	let candidates = vec![
		std::path::PathBuf::from("resolvers.txt"),
		std::env::current_exe()
			.ok()
			.and_then(|p| p.parent().map(|d| d.join("resolvers.txt")))
			.unwrap_or_default(),
	];

	for path in &candidates {
		if path.exists() {
			if let Ok(resolvers) = read_resolver_file(
				path.to_str().unwrap_or("resolvers.txt"),
			) {
				if !resolvers.is_empty() {
					return resolvers;
				}
			}
		}
	}

	// Hardcoded fallback if resolvers.txt is not found
	vec![
		ResolverConfig {
			label: "Cloudflare".to_string(),
			addr: "1.1.1.1:53".parse().unwrap(),
			intercepts_nxdomain: false,
		},
		ResolverConfig {
			label: "Google".to_string(),
			addr: "8.8.8.8:53".parse().unwrap(),
			intercepts_nxdomain: false,
		},
		ResolverConfig {
			label: "Quad9".to_string(),
			addr: "9.9.9.9:53".parse().unwrap(),
			intercepts_nxdomain: false,
		},
		ResolverConfig {
			label: "OpenDNS".to_string(),
			addr: "208.67.222.222:53".parse().unwrap(),
			intercepts_nxdomain: false,
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
}
