use clap::Parser;

use crate::stats::SortMode;

/// DNS resolver benchmark tool
#[derive(Parser, Debug)]
#[command(name = "dns-benchmark")]
#[command(about = "Benchmark DNS resolver performance over UDP, DoT, and DoH")]
pub struct Cli {
	/// DNS resolver address (repeatable, e.g. 1.1.1.1 or 1.1.1.1:53)
	#[arg(short = 'r', long = "resolver")]
	pub resolvers: Vec<String>,

	/// File containing resolver addresses (one per line)
	#[arg(short = 'f', long = "resolver-file")]
	pub resolver_file: Option<String>,

	/// Number of benchmark rounds
	#[arg(short = 'n', long = "rounds", default_value = "3")]
	pub rounds: u32,

	/// Also query AAAA records
	#[arg(long = "aaaa")]
	pub aaaa: bool,

	/// Enable DNSSEC (set DO bit on all queries)
	#[arg(long = "dnssec")]
	pub dnssec: bool,

	/// Output CSV file path
	#[arg(short = 'o', long = "output")]
	pub output: Option<String>,

	/// Save surviving resolver list to file (one per line)
	#[arg(long = "save-resolvers")]
	pub save_resolvers: Option<String>,

	/// Random seed for reproducible results
	#[arg(short = 's', long = "seed")]
	pub seed: Option<u64>,

	/// Exclude system resolvers from /etc/resolv.conf (included by default)
	#[arg(long = "no-system-resolvers")]
	pub no_system_resolvers: bool,

	/// Sort order for results
	#[arg(long = "sort", default_value = "score", value_enum)]
	pub sort: SortMode,

	/// Massive-scale scan: load ~11K public resolvers, discover survivors, benchmark with 30 rounds
	#[arg(long = "scan")]
	pub scan: bool,

	/// Exhaustive test: load ALL resolver lists (built-in + US scan + global), discover survivors, benchmark thoroughly
	#[arg(long = "exhaustive")]
	pub exhaustive: bool,
}
