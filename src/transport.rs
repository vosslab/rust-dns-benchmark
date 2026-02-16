use std::net::SocketAddr;
use std::time::Duration;

/// Configuration for a single DNS resolver
#[derive(Debug, Clone)]
pub struct ResolverConfig {
	pub label: String,
	pub addr: SocketAddr,
	/// Whether the resolver intercepts NXDOMAIN (set during characterization)
	pub intercepts_nxdomain: bool,
}

/// DNS query type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
	A,
	AAAA,
}

/// Result of a single DNS query
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct QueryResult {
	pub resolver: String,
	pub domain: String,
	pub query_type: QueryType,
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
}

/// Result of NXDOMAIN characterization for a single resolver
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CharacterizationResult {
	pub label: String,
	pub addr: SocketAddr,
	pub intercepts_nxdomain: bool,
	pub reachable: bool,
}
