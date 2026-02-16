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
	let tld_domains = match &cli.tld_domains {
		Some(path) => domains::read_domain_file(path)?,
		None => domains::default_tld_domains(),
	};

	// Build benchmark config
	let query_tld = !cli.no_tld;
	// Auto-enable discovery when resolver list is large (>20) unless disabled
	let discover = if cli.no_discover {
		false
	} else {
		cli.discover || resolvers.len() > 20
	};
	let config = BenchmarkConfig {
		rounds: cli.rounds,
		timeout: Duration::from_millis(cli.timeout),
		max_inflight: cli.concurrency,
		inter_query_spacing: Duration::from_millis(cli.spacing),
		query_aaaa: cli.aaaa,
		seed: cli.seed,
		dnssec: cli.dnssec,
		query_tld,
		discover,
		top_n: cli.top,
		max_resolver_ms: cli.max_resolver_ms as f64,
	};

	// Print configuration summary
	output::print_config_summary(
		&resolvers, warm_domains.len(), cold_domains.len(),
		tld_domains.len(), &config,
	);

	// Discovery mode: prefilter large resolver lists BEFORE characterization
	// This avoids wasting time characterizing resolvers that will be dropped
	if config.discover {
		resolvers = bench::run_discovery(&resolvers, &warm_domains, &config).await?;
		println!();
	}

	// Run NXDOMAIN interception characterization (only on surviving resolvers)
	bench::run_characterization(&mut resolvers, config.timeout).await;

	// Run benchmark
	println!("Running benchmark...");
	let mut results = bench::run_benchmark(
		&resolvers, &warm_domains, &cold_domains, &tld_domains, &config,
	).await?;

	// Filter out resolvers slower than the max latency threshold
	let before_count = results.len();
	results.retain(|r| r.stats.warm.p50_ms <= config.max_resolver_ms);
	let filtered_count = before_count - results.len();
	if filtered_count > 0 {
		println!(
			"Filtered {} resolver(s) with warm p50 > {} ms",
			filtered_count, config.max_resolver_ms as u64,
		);
	}

	// Re-rank after filtering
	for (i, r) in results.iter_mut().enumerate() {
		r.rank = i + 1;
		r.tie_group = None;
	}

	// Print results table
	output::print_results_table(&results, config.query_tld);

	// Write CSV if requested
	if let Some(path) = &cli.output {
		output::write_csv(path, &results, config.query_tld)?;
	}

	Ok(())
}
