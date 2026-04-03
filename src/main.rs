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

/// GRC-compatible exit codes for automation and scripting.
///
/// 0 = success, 1 = file not found, 2 = no IPs in file,
/// 3 = too many resolvers, 4 = no resolvers to test,
/// 5 = no connectivity, 6 = lost connectivity during test,
/// 7 = log file creation failure, 8 = log file write failure.
fn error_to_exit_code(msg: &str) -> u8 {
	if msg.contains("No such file") || msg.contains("not found") {
		1
	} else if msg.contains("no IPs") || msg.contains("No IPs") {
		2
	} else if msg.contains("too many") || msg.contains("Too many") {
		3
	} else if msg.contains("no resolvers") || msg.contains("No resolvers") {
		4
	} else if msg.contains("no connectivity") || msg.contains("No connectivity") {
		5
	} else if msg.contains("lost connectivity") || msg.contains("Lost connectivity") {
		6
	} else if msg.contains("create log") || msg.contains("Create log") {
		7
	} else if msg.contains("write log") || msg.contains("Write log") {
		8
	} else {
		1
	}
}

#[tokio::main]
async fn main() -> ExitCode {
	match run().await {
		Ok(()) => ExitCode::from(0),
		Err(e) => {
			let msg = format!("{}", e);
			eprintln!("Error: {}", msg);
			ExitCode::from(error_to_exit_code(&msg))
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

	// Scan mode: load ~11K public resolvers for massive-scale testing
	if cli.scan {
		let scan_list = resolver::scan_resolvers();
		if scan_list.is_empty() {
			anyhow::bail!("Scan list not found (resolvers/scan_us.txt). Cannot run --scan mode.");
		}
		println!("Scan mode: loading {} public resolvers for massive-scale test", scan_list.len());
		resolvers.extend(scan_list);
	}

	// When no resolvers explicitly specified (and not scanning), load the master lists by default
	if !user_specified && !cli.scan {
		resolvers.extend(resolver::default_resolvers());
		if !cli.no_ipv6_resolvers {
			resolvers.extend(resolver::default_ipv6_resolvers());
		}
		if !cli.no_doh_resolvers {
			resolvers.extend(resolver::default_doh_resolvers());
		}
		if !cli.no_dot_resolvers {
			resolvers.extend(resolver::default_dot_resolvers());
		}
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
	let dotcom_domains = match &cli.dotcom_domains {
		Some(path) => domains::read_domain_file(path)?,
		None => domains::default_dotcom_domains(),
	};
	let dnssec_domains = match &cli.dnssec_domains {
		Some(path) => domains::read_domain_file(path)?,
		None => domains::default_dnssec_domains(),
	};

	// Build benchmark config
	let query_tld = !cli.no_tld;
	// Auto-enable discovery when resolver list is large (>20) unless disabled
	// Scan mode always forces discovery on
	let discover = if cli.scan {
		true
	} else if cli.no_discover {
		false
	} else {
		cli.discover || resolvers.len() > 20
	};
	// Scan mode overrides rounds to 30 for thorough testing
	let rounds = if cli.scan { 30 } else { cli.rounds };
	let query_dotcom = !cli.no_dotcom;
	let query_dnssec_domains = cli.dnssec;
	let config = BenchmarkConfig {
		rounds,
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
		query_dotcom,
		char_timeout: Duration::from_millis(cli.char_timeout),
		char_attempts: cli.char_attempts,
		query_dnssec_domains,
	};

	// Track resolver counts through the pipeline
	let initial_count = resolvers.len();

	// Print configuration summary
	output::print_config_summary(
		&resolvers, warm_domains.len(), cold_domains.len(),
		tld_domains.len(), dotcom_domains.len(),
		dnssec_domains.len(), &config,
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

	let post_discovery_count = resolvers.len();

	// Run reverse DNS (PTR) lookups and NXDOMAIN interception characterization
	rdns::resolve_ptr_names(&mut resolvers, config.timeout).await;
	bench::run_characterization(&mut resolvers, &config, &nxdomain_domains).await;

	let post_char_count = resolvers.len();

	// Run benchmark
	println!("Running benchmark...");
	let mut results = bench::run_benchmark(
		&resolvers, &warm_domains, &cold_domains, &tld_domains,
		&dotcom_domains, &dnssec_domains, &config, &doh_clients,
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

	// Print pipeline summary
	let final_count = results.len();
	output::print_pipeline_summary(
		initial_count, post_discovery_count, post_char_count, final_count,
	);

	// Print results table and conclusions
	output::print_results_table(&results, config.query_tld, config.query_dotcom, config.query_dnssec_domains);
	output::print_conclusions(&results);

	// Write CSV if requested
	if let Some(path) = &cli.output {
		output::write_csv(path, &results, config.query_tld, config.query_dotcom, config.query_dnssec_domains)?;
	}

	// Save resolver list if requested
	if let Some(path) = &cli.save_resolvers {
		output::write_resolver_list(path, &results)?;
	}

	Ok(())
}
