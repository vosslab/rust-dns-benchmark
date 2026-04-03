use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use crate::stats::SortMode;

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
	/// Enable TLD diversity measurement
	pub query_tld: bool,
	/// Enable discovery prefilter mode
	pub discover: bool,
	/// Number of top resolvers to keep in discovery mode
	pub top_n: usize,
	/// Maximum resolver latency in ms; resolvers above this are dropped from results
	pub max_resolver_ms: f64,
	/// Sort mode for ranking results
	pub sort_mode: SortMode,
	/// Pin system resolvers to the top of results
	pub pin_system: bool,
	/// Enable mid-benchmark sidelining of slow resolvers
	pub sideline: bool,
	/// Maximum p50 latency (ms) before a resolver is sidelined mid-benchmark
	pub sideline_ms: f64,
}
