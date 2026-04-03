use clap::Parser;
use clap::ValueEnum;

/// Benchmark level controlling coverage scope and confidence depth
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BenchLevel {
	/// Built-in resolvers only, few rounds (fastest)
	Quick,
	/// Global discovery + qualification, benchmark finalists
	Medium,
	/// Global discovery + staged elimination tournament
	Slow,
	/// Global discovery + full benchmark on all survivors (most thorough)
	Exhaustive,
}

impl std::fmt::Display for BenchLevel {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			BenchLevel::Quick => write!(f, "quick"),
			BenchLevel::Medium => write!(f, "medium"),
			BenchLevel::Slow => write!(f, "slow"),
			BenchLevel::Exhaustive => write!(f, "exhaustive"),
		}
	}
}

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

	/// Number of benchmark rounds (overrides level default)
	#[arg(short = 'n', long = "rounds")]
	pub rounds: Option<u32>,

	/// Output CSV file path
	#[arg(short = 'o', long = "output")]
	pub output: Option<String>,

	/// Save surviving resolver list to file (one per line)
	#[arg(long = "save-resolvers")]
	pub save_resolvers: Option<String>,

	/// Benchmark level: quick, medium, slow, exhaustive
	#[arg(short = 'l', long = "level", default_value = "quick")]
	pub level: BenchLevel,

	/// Print config summary and exit without running benchmark
	#[arg(long = "no-test")]
	pub no_test: bool,
}
