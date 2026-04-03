use clap::Parser;

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

	/// Output CSV file path
	#[arg(short = 'o', long = "output")]
	pub output: Option<String>,

	/// Save surviving resolver list to file (one per line)
	#[arg(long = "save-resolvers")]
	pub save_resolvers: Option<String>,

	/// Exhaustive test: load ALL resolver lists (built-in + global), discover survivors, benchmark thoroughly
	#[arg(long = "exhaustive")]
	pub exhaustive: bool,

	/// Print config summary and exit without running benchmark
	#[arg(long = "no-test")]
	pub no_test: bool,
}
