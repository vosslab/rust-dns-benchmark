use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use crate::stats::SortMode;

// Hardcoded benchmark defaults (CLI minimalism: not user-configurable)
pub const DEFAULT_TIMEOUT_MS: u64 = 2000;
pub const DEFAULT_CONCURRENCY: usize = 64;
pub const DEFAULT_SPACING_MS: u64 = 25;
pub const DEFAULT_MAX_RESOLVER_MS: f64 = 1000.0;
pub const DEFAULT_SIDELINE_MS: f64 = 500.0;
pub const DEFAULT_CHAR_TIMEOUT_MS: u64 = 100;
pub const DEFAULT_CHAR_ATTEMPTS: u32 = 10;
pub const DEFAULT_QUERY_AAAA: bool = true;
pub const DEFAULT_DNSSEC: bool = true;
pub const DEFAULT_INCLUDE_SYSTEM_RESOLVERS: bool = true;
pub const DEFAULT_SORT: &str = "score";
// Level-specific round defaults
pub const DEFAULT_QUICK_ROUNDS: u32 = 3;
pub const DEFAULT_MEDIUM_ROUNDS: u32 = 5;
pub const DEFAULT_SLOW_ROUNDS: u32 = 7;
pub const DEFAULT_EXHAUSTIVE_ROUNDS: u32 = 30;
// Medium mode: max resolvers promoted from qualification to full benchmark
pub const DEFAULT_MEDIUM_BUDGET: usize = 200;
// Slow mode: purge ratio and minimum finalist floor
pub const DEFAULT_SLOW_PURGE_RATIO: f64 = 0.5;
pub const DEFAULT_SLOW_FINALIST_MIN: usize = 250;

/// DNS transport protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsTransport {
	/// Plain UDP (default, port 53)
	Udp,
	/// DNS over TLS (RFC 7858, default port 853)
	Dot {
		/// TLS SNI hostname for certificate validation
		hostname: String,
	},
	/// DNS over HTTPS (RFC 8484, default port 443)
	Doh {
		/// Full HTTPS URL (e.g. "https://1.1.1.1/dns-query")
		url: String,
	},
}

impl fmt::Display for DnsTransport {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			DnsTransport::Udp => write!(f, "UDP"),
			DnsTransport::Dot { .. } => write!(f, "DoT"),
			DnsTransport::Doh { .. } => write!(f, "DoH"),
		}
	}
}

/// Configuration for a single DNS resolver
#[derive(Debug, Clone)]
pub struct ResolverConfig {
	pub label: String,
	pub addr: SocketAddr,
	/// Transport protocol (UDP, DoT, or DoH)
	pub transport: DnsTransport,
	/// Whether the resolver intercepts NXDOMAIN (set during characterization)
	pub intercepts_nxdomain: bool,
	/// Whether this resolver came from the system's /etc/resolv.conf
	pub is_system: bool,
	/// Reverse DNS (PTR) hostname for the resolver IP
	pub ptr_name: Option<String>,
	/// Whether the resolver protects against DNS rebinding attacks
	pub rebinding_protection: Option<bool>,
	/// Whether the resolver validates DNSSEC signatures
	pub validates_dnssec: Option<bool>,
	/// ISO 2-letter country code from public-dns.info metadata
	pub country_code: Option<String>,
	/// Autonomous system organization name
	pub as_org: Option<String>,
	/// Reliability score (0.0-1.0) from public-dns.info
	pub reliability: Option<f64>,
}

//============================================
/// Classify a resolver IP as "system", "private" (RFC1918), or "public".
/// Used for diagnostic tagging in telemetry, not for promotion decisions.
pub fn resolver_class(resolver: &ResolverConfig) -> &'static str {
	if resolver.is_system {
		return "system";
	}
	match resolver.addr.ip() {
		std::net::IpAddr::V4(ip) => {
			let octets = ip.octets();
			// 10.0.0.0/8
			if octets[0] == 10 {
				return "private";
			}
			// 172.16.0.0/12
			if octets[0] == 172 && (16..=31).contains(&octets[1]) {
				return "private";
			}
			// 192.168.0.0/16
			if octets[0] == 192 && octets[1] == 168 {
				return "private";
			}
			"public"
		}
		std::net::IpAddr::V6(_) => "public",
	}
}

/// DNS query type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
	A,
	#[allow(clippy::upper_case_acronyms)]
	AAAA,
}

/// Result of a single DNS query
#[derive(Debug, Clone)]
pub struct QueryResult {
	pub resolver: String,
	#[allow(dead_code)]
	pub domain: String,
	#[allow(dead_code)]
	pub query_type: QueryType,
	#[allow(dead_code)]
	pub rcode: Option<String>,
	pub latency: Duration,
	pub success: bool,
	pub timeout: bool,
}

/// Benchmark configuration
#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
	pub rounds: u32,
	pub timeout: Duration,
	pub max_inflight: usize,
	pub inter_query_spacing: Duration,
	pub query_aaaa: bool,
	pub seed: Option<u64>,
	/// Enable DNSSEC (DO bit) on all queries
	pub dnssec: bool,
	/// Enable discovery prefilter mode
	pub discover: bool,
	/// Benchmark level
	pub level: crate::cli::BenchLevel,
	/// Maximum resolver latency in ms; resolvers above this are dropped from results
	pub max_resolver_ms: f64,
	/// Sort mode for ranking results
	pub sort_mode: SortMode,
	/// Telemetry logger for JSONL debug output
	pub telemetry: crate::telemetry::TelemetryLog,
}
