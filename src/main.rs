mod bench;
mod cli;
mod dns;
mod domains;
mod output;
mod rdns;
mod resolver;
mod stats;
mod transport;

use clap::Parser;
use std::process::ExitCode;
use std::time::Duration;

use crate::cli::Cli;
use crate::transport::BenchmarkConfig;

#[tokio::main]
async fn main() -> ExitCode {
	match run().await {
		Ok(()) => ExitCode::from(0),
		Err(e) => {
			let msg = format!("{}", e);
			eprintln!("Error: {}", msg);
			// Map error messages to GRC-compatible exit codes
			if msg.contains("No such file") || msg.contains("not found") {
				ExitCode::from(1)
			} else if msg.contains("no resolvers") || msg.contains("No resolvers") {
				ExitCode::from(4)
			} else if msg.contains("no connectivity") || msg.contains("No connectivity") {
				ExitCode::from(5)
			} else {
				ExitCode::from(1)
			}
		}
	}
}

async fn run() -> anyhow::Result<()> {
	let cli = Cli::parse();

	// Collect resolvers from all sources
	let mut resolvers = Vec::new();
	let user_specified = !cli.resolvers.is_empty() || cli.resolver_file.is_some();

	// From CLI flags
	for r in &cli.resolvers {
		resolvers.push(resolver::parse_resolver(r)?);
	}

	// From resolver file
	if let Some(path) = &cli.resolver_file {
		resolvers.extend(resolver::read_resolver_file(path)?);
	}

	// When no resolvers explicitly specified, load the master list by default
	if !user_specified {
		resolvers.extend(resolver::default_resolvers());
	}

	// System resolvers (included by default, opt out with --no-system-resolvers)
	if !cli.no_system_resolvers {
		let mut sys = resolver::system_resolvers();
		// Deduplicate: skip system resolvers already in the list
		sys.retain(|s| !resolvers.iter().any(|r| r.addr.ip() == s.addr.ip()));
		resolvers.extend(sys);
	}

	// Bail early if no resolvers to test
	if resolvers.is_empty() {
		anyhow::bail!("No resolvers to test. Provide resolvers via -r, -f, or system defaults.");
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
	let nxdomain_domains = match &cli.nxdomain_domains {
		Some(path) => domains::read_domain_file(path)?,
		None => domains::default_nxdomain_domains(),
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
		sort_mode: cli.sort,
		pin_system: !cli.no_pin_system,
		sideline: !cli.no_sideline,
		sideline_ms: cli.sideline_ms as f64,
	};

	// Print configuration summary
	output::print_config_summary(
		&resolvers, warm_domains.len(), cold_domains.len(),
		tld_domains.len(), &config,
	);

	// Build DoH client pool for any DoH resolvers
	let doh_clients = bench::build_doh_client_pool(&resolvers);

	// Discovery mode: prefilter large resolver lists BEFORE characterization
	// This avoids wasting time characterizing resolvers that will be dropped
	if config.discover {
		resolvers = bench::run_discovery(
			&resolvers, &warm_domains, &config, &doh_clients,
		).await?;
		println!();
	}

	// Run reverse DNS (PTR) lookups and NXDOMAIN interception characterization
	rdns::resolve_ptr_names(&mut resolvers, config.timeout).await;
	bench::run_characterization(&mut resolvers, config.timeout, &nxdomain_domains).await;

	// Run benchmark
	println!("Running benchmark...");
	let mut results = bench::run_benchmark(
		&resolvers, &warm_domains, &cold_domains, &tld_domains, &config,
		&doh_clients,
	).await?;

	// Filter out resolvers with <50% success rate (too noisy to report)
	let before_count = results.len();
	results.retain(|r| r.stats.success_rate >= 50.0);
	let low_success_count = before_count - results.len();
	if low_success_count > 0 {
		println!(
			"Filtered {} resolver(s) with success rate < 50%",
			low_success_count,
		);
	}

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

	// Pin system resolvers to top if requested
	if config.pin_system {
		let (mut pinned, mut rest): (Vec<_>, Vec<_>) = results
			.into_iter()
			.partition(|r| r.is_system);
		// Preserve sort order within each group
		pinned.append(&mut rest);
		results = pinned;
	}

	// Re-rank after filtering and pinning
	for (i, r) in results.iter_mut().enumerate() {
		r.rank = i + 1;
		r.tie_group = None;
	}

	// Print results table and conclusions
	output::print_results_table(&results, config.query_tld);
	output::print_conclusions(&results);

	// Write CSV if requested
	if let Some(path) = &cli.output {
		output::write_csv(path, &results, config.query_tld)?;
	}

	// Save resolver list if requested
	if let Some(path) = &cli.save_resolvers {
		output::write_resolver_list(path, &results)?;
	}

	Ok(())
}
