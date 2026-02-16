use clap::Parser;

/// DNS resolver benchmark tool
#[derive(Parser, Debug)]
#[command(name = "dns-benchmark")]
#[command(about = "Benchmark DNS resolver performance over UDP")]
pub struct Cli {
	/// DNS resolver address (repeatable, e.g. 1.1.1.1 or 1.1.1.1:53)
	#[arg(short = 'r', long = "resolver")]
	pub resolvers: Vec<String>,

	/// File containing resolver addresses (one per line)
	#[arg(short = 'f', long = "resolver-file")]
	pub resolver_file: Option<String>,

	/// File containing warm (cached) domains to query
	#[arg(long = "warm-domains")]
	pub warm_domains: Option<String>,

	/// File containing cold (uncached) domains to query
	#[arg(long = "cold-domains")]
	pub cold_domains: Option<String>,

	/// Number of benchmark rounds
	#[arg(short = 'n', long = "rounds", default_value = "3")]
	pub rounds: u32,

	/// Query timeout in milliseconds
	#[arg(short = 't', long = "timeout", default_value = "5000")]
	pub timeout: u64,

	/// Maximum concurrent in-flight queries
	#[arg(short = 'c', long = "concurrency", default_value = "64")]
	pub concurrency: usize,

	/// Inter-query spacing in milliseconds
	#[arg(long = "spacing", default_value = "5")]
	pub spacing: u64,

	/// Also query AAAA records
	#[arg(long = "aaaa")]
	pub aaaa: bool,

	/// Output CSV file path
	#[arg(short = 'o', long = "output")]
	pub output: Option<String>,

	/// Random seed for reproducible results
	#[arg(short = 's', long = "seed")]
	pub seed: Option<u64>,

	/// Include system resolvers from /etc/resolv.conf
	#[arg(long = "system-resolvers")]
	pub system_resolvers: bool,
}
