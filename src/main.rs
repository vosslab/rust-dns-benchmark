mod bench;
mod cli;
mod dns;
mod domains;
mod output;
mod rdns;
mod resolver;
mod stats;
mod telemetry;
mod transport;

use clap::Parser;
use std::process::ExitCode;
use std::time::Duration;

use crate::cli::Cli;
use crate::transport::{BenchmarkConfig, DEFAULT_TIMEOUT_MS, DEFAULT_CONCURRENCY,
	DEFAULT_SPACING_MS, DEFAULT_TOP_N, DEFAULT_MAX_RESOLVER_MS};

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

	// Exhaustive mode: download CSV with metadata, fall back to local scan_global.txt
	if cli.exhaustive {
		match resolver::download_exhaustive_csv().await {
			Ok(csv_resolvers) if !csv_resolvers.is_empty() => {
				println!("Exhaustive mode: loaded {} resolvers from public-dns.info CSV", csv_resolvers.len());
				resolvers.extend(csv_resolvers);
			}
			Ok(_) | Err(_) => {
				// Fallback to local scan_global.txt or download plain text list
				println!("CSV download failed or empty, falling back to local resolver list");
				let mut global_list = resolver::scan_global_resolvers();
				if global_list.is_empty() {
					println!("Downloading global nameserver list from public-dns.info...");
					let global_path = resolver::download_global_list().await?;
					global_list = resolver::read_resolver_file(&global_path)?;
				}
				if global_list.is_empty() {
					anyhow::bail!("Global scan list is empty after download. Cannot run --exhaustive mode.");
				}
				println!("Exhaustive mode: loading {} global public resolvers from fallback", global_list.len());
				resolvers.extend(global_list);
			}
		}
	}

	// Scan mode: load ~11K US public resolvers for massive-scale testing
	if cli.scan && !cli.exhaustive {
		let scan_list = resolver::scan_resolvers();
		if scan_list.is_empty() {
			anyhow::bail!("Scan list not found (resolvers/scan_us.txt). Cannot run --scan mode.");
		}
		println!("Scan mode: loading {} US public resolvers for massive-scale test", scan_list.len());
		resolvers.extend(scan_list);
	}

	// Load built-in resolver lists (always, unless user specified explicit resolvers)
	if !user_specified {
		resolvers.extend(resolver::default_resolvers());
		resolvers.extend(resolver::default_ipv6_resolvers());
		resolvers.extend(resolver::default_doh_resolvers());
		resolvers.extend(resolver::default_dot_resolvers());
	}

	// System resolvers (included by default, opt out with --no-system-resolvers)
	if !cli.no_system_resolvers {
		let mut sys = resolver::system_resolvers();
		// Deduplicate: skip system resolvers already in the list
		sys.retain(|s| !resolvers.iter().any(|r| r.addr.ip() == s.addr.ip()));
		resolvers.extend(sys);
	}

	// Deduplicate all resolvers by IP address, keeping first occurrence
	let mut seen_ips = std::collections::HashSet::new();
	resolvers.retain(|r| seen_ips.insert(r.addr.ip()));

	// Bail early if no resolvers to test
	if resolvers.is_empty() {
		anyhow::bail!("No resolvers to test. Provide resolvers via -r, -f, or system defaults.");
	}

	// Load query domain categories (from file or built-in defaults)
	let mut categories = match &cli.query_domains {
		Some(path) => domains::load_query_domains_file(path)?,
		None => domains::load_default_query_domains(),
	};

	// Only include DNSSEC category when --dnssec is enabled
	if !cli.dnssec {
		categories.remove("dnssec");
	}

	// Load NXDOMAIN test domains (used for characterization, not benchmarking)
	let nxdomain_domains = domains::default_nxdomain_domains();

	// Parse sort mode and validate against loaded categories
	let sort_mode = stats::parse_sort_mode(&cli.sort);
	if let stats::SortMode::Category(ref name) = sort_mode {
		if !categories.contains_key(name) {
			let valid: Vec<&str> = categories.keys().map(|s| s.as_str()).collect();
			anyhow::bail!(
				"Unknown sort category '{}'. Valid categories: score, name, {}",
				name, valid.join(", ")
			);
		}
	}

	// Auto-enable discovery when resolver list is large (>20)
	// Scan and exhaustive modes always force discovery on
	let discover = if cli.scan || cli.exhaustive {
		true
	} else {
		resolvers.len() > 20
	};
	// Scan/exhaustive modes override rounds to 30 for thorough testing
	let rounds = if cli.scan || cli.exhaustive { 30 } else { cli.rounds };
	let config = BenchmarkConfig {
		rounds,
		timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
		max_inflight: DEFAULT_CONCURRENCY,
		inter_query_spacing: Duration::from_millis(DEFAULT_SPACING_MS),
		query_aaaa: cli.aaaa,
		seed: cli.seed,
		dnssec: cli.dnssec,
		discover,
		top_n: DEFAULT_TOP_N,
		max_resolver_ms: DEFAULT_MAX_RESOLVER_MS,
		sort_mode,
		telemetry: telemetry::TelemetryLog::new(true),
	};

	// Determine run mode for telemetry
	let mode = if cli.exhaustive { "exhaustive" } else if cli.scan { "scan" } else { "default" };
	config.telemetry.log_config(rounds, DEFAULT_TOP_N, DEFAULT_SPACING_MS, mode, resolvers.len());

	// Track resolver counts through the pipeline
	let initial_count = resolvers.len();
	config.telemetry.log_pipeline("loaded", initial_count);

	// Print configuration summary
	output::print_config_summary(&resolvers, &categories, &config);

	// Early exit if --no-test was requested
	if cli.no_test {
		println!("--no-test: exiting without running benchmark.");
		return Ok(());
	}

	// Build DoH client pool for any DoH resolvers
	let doh_clients = bench::build_doh_client_pool(&resolvers);

	// Discovery mode: prefilter large resolver lists BEFORE characterization
	// This avoids wasting time characterizing resolvers that will be dropped
	if config.discover {
		resolvers = bench::run_discovery(
			&resolvers, &categories, &config, &doh_clients,
		).await?;
		println!();
	}

	let post_discovery_count = resolvers.len();
	config.telemetry.log_pipeline("after_discovery", post_discovery_count);

	// Run reverse DNS (PTR) lookups and NXDOMAIN interception characterization
	rdns::resolve_ptr_names(&mut resolvers, config.timeout).await;
	bench::run_characterization(&mut resolvers, &config, &nxdomain_domains).await;

	let post_char_count = resolvers.len();
	config.telemetry.log_pipeline("after_characterization", post_char_count);

	// Run benchmark
	println!("Running benchmark...");
	let mut results = bench::run_benchmark(
		&resolvers, &categories, &config, &doh_clients,
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
	// Use first category p50 as proxy for the warm/cached latency check
	let first_cat = categories.keys().next().cloned();
	if let Some(ref cat_name) = first_cat {
		let before_count = results.len();
		results.retain(|r| {
			r.stats.categories.get(cat_name)
				.map(|s| s.p50_ms <= config.max_resolver_ms)
				.unwrap_or(true)
		});
		let filtered_count = before_count - results.len();
		if filtered_count > 0 {
			println!(
				"Filtered {} resolver(s) with {} p50 > {} ms",
				filtered_count, cat_name, config.max_resolver_ms as u64,
			);
		}
	}

	// Pin system resolvers to top of results
	let (mut pinned, mut rest): (Vec<_>, Vec<_>) = results
		.into_iter()
		.partition(|r| r.is_system);
	// Preserve sort order within each group
	pinned.append(&mut rest);
	results = pinned;

	// Re-rank after filtering and pinning
	for (i, r) in results.iter_mut().enumerate() {
		r.rank = i + 1;
		r.tie_group = None;
	}

	// Log final results to telemetry
	for r in &results {
		// Use first category for telemetry score/p50
		let (score, p50) = first_cat.as_ref()
			.and_then(|cat| r.stats.categories.get(cat))
			.map(|s| (s.score, s.p50_ms))
			.unwrap_or((r.stats.overall_score, 0.0));
		config.telemetry.log_result(r.rank, &r.stats.addr, &r.stats.label, score, p50);
	}

	// Print pipeline summary
	let final_count = results.len();
	config.telemetry.log_pipeline("final_results", final_count);
	output::print_pipeline_summary(
		initial_count, post_discovery_count, post_char_count, final_count, DEFAULT_TOP_N,
	);

	// Print results table and conclusions
	output::print_results_table(&results);
	output::print_conclusions(&results);

	// Write CSV if requested
	if let Some(path) = &cli.output {
		output::write_csv(path, &results)?;
	}

	// Save resolver list if requested
	if let Some(path) = &cli.save_resolvers {
		output::write_resolver_list(path, &results)?;
	}

	Ok(())
}
