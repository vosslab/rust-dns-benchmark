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

	/// File containing NXDOMAIN test domains for interception detection
	#[arg(long = "nxdomain-domains")]
	pub nxdomain_domains: Option<String>,

	/// File containing TLD-diverse domains to query
	#[arg(long = "tld-domains")]
	pub tld_domains: Option<String>,

	/// Disable TLD diversity measurement
	#[arg(long = "no-tld")]
	pub no_tld: bool,

	/// Number of benchmark rounds
	#[arg(short = 'n', long = "rounds", default_value = "3")]
	pub rounds: u32,

	/// Query timeout in milliseconds
	#[arg(short = 't', long = "timeout", default_value = "2000")]
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

	/// Enable DNSSEC (set DO bit on all queries)
	#[arg(long = "dnssec")]
	pub dnssec: bool,

	/// Enable discovery mode to prefilter a large resolver list
	#[arg(long = "discover")]
	pub discover: bool,

	/// Number of top resolvers to keep in discovery mode
	#[arg(long = "top", default_value = "50")]
	pub top: usize,

	/// Disable auto-discovery (benchmark all resolvers without prefiltering)
	#[arg(long = "no-discover")]
	pub no_discover: bool,

	/// Maximum resolver latency in ms; drop resolvers slower than this from results
	#[arg(long = "max-resolver-ms", default_value = "1000")]
	pub max_resolver_ms: u64,

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
