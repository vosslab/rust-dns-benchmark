mod bench;
mod cli;
mod dns;
mod domains;
mod output;
mod resolver;
mod stats;
mod transport;

use clap::Parser;
use std::time::Duration;

use crate::cli::Cli;
use crate::transport::BenchmarkConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	let cli = Cli::parse();

	// Collect resolvers from all sources
	let mut resolvers = Vec::new();

	// From CLI flags
	for r in &cli.resolvers {
		resolvers.push(resolver::parse_resolver(r)?);
	}

	// From resolver file
	if let Some(path) = &cli.resolver_file {
		resolvers.extend(resolver::read_resolver_file(path)?);
	}

	// System resolvers
	if cli.system_resolvers {
		resolvers.extend(resolver::system_resolvers());
	}

	// Fall back to defaults if no resolvers specified
	if resolvers.is_empty() {
		resolvers = resolver::default_resolvers();
	}

	// Collect domains from files or defaults
	let warm_domains = match &cli.warm_domains {
		Some(path) => domains::read_domain_file(path)?,
		None => domains::default_warm_domains(),
	};
	let cold_domains = match &cli.cold_domains {
		Some(path) => domains::read_domain_file(path)?,
		None => domains::default_cold_domains(),
	};

	// Build benchmark config
	let config = BenchmarkConfig {
		rounds: cli.rounds,
		timeout: Duration::from_millis(cli.timeout),
		max_inflight: cli.concurrency,
		inter_query_spacing: Duration::from_millis(cli.spacing),
		query_aaaa: cli.aaaa,
		seed: cli.seed,
	};

	// Print configuration summary
	output::print_config_summary(&resolvers, warm_domains.len(), cold_domains.len(), &config);

	// Run benchmark
	println!("Running benchmark...");
	let results = bench::run_benchmark(
		&resolvers, &warm_domains, &cold_domains, &config,
	).await?;

	// Print results table
	output::print_results_table(&results);

	// Write CSV if requested
	if let Some(path) = &cli.output {
		output::write_csv(path, &results)?;
	}

	Ok(())
}
