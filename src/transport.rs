use std::net::SocketAddr;
use std::time::Duration;

/// Configuration for a single DNS resolver
#[derive(Debug, Clone)]
pub struct ResolverConfig {
	pub label: String,
	pub addr: SocketAddr,
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
}
