mod bench;
mod cli;
mod dns;
mod domains;
mod output;
mod rdns;
mod record;
mod resolver;
mod stats;
mod telemetry;
mod transport;

use clap::Parser;
use std::process::ExitCode;
use std::time::Duration;

use crate::cli::{BenchLevel, Cli};
use crate::transport::{BenchmarkConfig, DEFAULT_TIMEOUT_MS, DEFAULT_CONCURRENCY,
	DEFAULT_SPACING_MS, DEFAULT_MAX_RESOLVER_MS,
	DEFAULT_QUERY_AAAA, DEFAULT_DNSSEC, DEFAULT_INCLUDE_SYSTEM_RESOLVERS,
	DEFAULT_SORT, DEFAULT_QUICK_ROUNDS, DEFAULT_MEDIUM_ROUNDS,
	DEFAULT_SLOW_ROUNDS, DEFAULT_EXHAUSTIVE_ROUNDS};

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
	// Install the rustls ring crypto provider before any TLS connections
	rustls::crypto::ring::default_provider()
		.install_default()
		.expect("Failed to install rustls crypto provider");
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
	let level = cli.level;

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

	// Global CSV download for medium, slow, and exhaustive levels
	let needs_global = matches!(level, BenchLevel::Medium | BenchLevel::Slow | BenchLevel::Exhaustive);
	if needs_global {
		match resolver::download_exhaustive_csv().await {
			Ok(csv_resolvers) if !csv_resolvers.is_empty() => {
				println!("{} mode: loaded {} resolvers from public-dns.info CSV", level, csv_resolvers.len());
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
					anyhow::bail!("Global scan list is empty after download. Cannot run {} mode.", level);
				}
				println!("{} mode: loading {} global public resolvers from fallback", level, global_list.len());
				resolvers.extend(global_list);
			}
		}
	}

	// Load built-in resolver lists (always, unless user specified explicit resolvers)
	if !user_specified {
		resolvers.extend(resolver::default_resolvers());
		resolvers.extend(resolver::default_ipv6_resolvers());
		resolvers.extend(resolver::default_doh_resolvers());
		resolvers.extend(resolver::default_dot_resolvers());
	}

	// System resolvers (compile-time default: always included)
	if DEFAULT_INCLUDE_SYSTEM_RESOLVERS {
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

	// Load query domain categories from built-in defaults
	let mut categories = domains::load_default_query_domains();

	// Remove DNSSEC category if DNSSEC is disabled at compile time
	if !DEFAULT_DNSSEC {
		categories.remove("dnssec");
	}

	// Load NXDOMAIN test domains (used for characterization, not benchmarking)
	let nxdomain_domains = domains::default_nxdomain_domains();

	// Sort mode (compile-time default)
	let sort_mode = stats::parse_sort_mode(DEFAULT_SORT);

	// Determine rounds: user override via --rounds, or level default
	let default_rounds = match level {
		BenchLevel::Quick => DEFAULT_QUICK_ROUNDS,
		BenchLevel::Medium => DEFAULT_MEDIUM_ROUNDS,
		BenchLevel::Slow => DEFAULT_SLOW_ROUNDS,
		BenchLevel::Exhaustive => DEFAULT_EXHAUSTIVE_ROUNDS,
	};
	let rounds = cli.rounds.unwrap_or(default_rounds);

	// Auto-enable discovery when resolver list is large (>20)
	let discover = needs_global || resolvers.len() > 20;

	let config = BenchmarkConfig {
		rounds,
		timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
		max_inflight: DEFAULT_CONCURRENCY,
		inter_query_spacing: Duration::from_millis(DEFAULT_SPACING_MS),
		query_aaaa: DEFAULT_QUERY_AAAA,
		seed: None,
		dnssec: DEFAULT_DNSSEC,
		discover,
		level,
		max_resolver_ms: DEFAULT_MAX_RESOLVER_MS,
		sort_mode,
		telemetry: telemetry::TelemetryLog::new(true),
	};

	// Log config to telemetry
	config.telemetry.log_config(rounds, DEFAULT_SPACING_MS, &level.to_string(), resolvers.len());

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

	// Wrap all resolvers into records -- single creation point for the entire pipeline
	let mut records: Vec<record::ResolverRecord> = resolvers.into_iter()
		.map(record::ResolverRecord::new)
		.collect();

	// Track phase timings for summary
	let mut phase_timings: Vec<(&str, std::time::Duration, Option<(usize, usize)>)> = Vec::new();
	let pipeline_start = std::time::Instant::now();

	// Discovery: reachability screen for large resolver lists
	if config.discover {
		let phase_start = std::time::Instant::now();
		let before = records.len();
		bench::run_discovery(
			&mut records, &categories, &config, &doh_clients,
		).await;
		// Retain only records that passed discovery (missing result = failure)
		records.retain(|r| r.discovery.as_ref().map_or(false, |d| d.passed));
		let discovery_elapsed = phase_start.elapsed();
		config.telemetry.log_phase("discovery", discovery_elapsed.as_secs(), before, records.len());
		phase_timings.push(("Discovery", discovery_elapsed, Some((before, records.len()))));
		println!();
	}

	let post_discovery_count = records.len();
	config.telemetry.log_pipeline("after_discovery", post_discovery_count);

	// Run reverse DNS (PTR) lookups and NXDOMAIN interception characterization
	let char_phase_start = std::time::Instant::now();
	let char_before = records.len();
	rdns::resolve_ptr_names(&mut records, config.timeout).await;
	bench::run_characterization(&mut records, &config, &nxdomain_domains).await;
	let char_elapsed = char_phase_start.elapsed();
	config.telemetry.log_phase("characterization", char_elapsed.as_secs(), char_before, records.len());
	phase_timings.push(("Characterization", char_elapsed, Some((char_before, records.len()))));

	let post_char_count = records.len();
	config.telemetry.log_pipeline("after_characterization", post_char_count);

	// Medium mode: run qualification pass and promote finalists
	if level == BenchLevel::Medium {
		let qual_start = std::time::Instant::now();
		let qual_before = records.len();
		bench::run_qualification(
			&mut records, &categories, &config, &doh_clients,
		).await;
		// Retain only promoted records (missing qualification = not promoted)
		records.retain(|r| r.qualification.as_ref().map_or(false, |q| q.promoted));
		phase_timings.push(("Qualification", qual_start.elapsed(), Some((qual_before, records.len()))));
		config.telemetry.log_pipeline("after_qualification", records.len());
	}

	// Run benchmark (writes BenchmarkResult onto existing records in place)
	println!("Running benchmark...");
	let bench_start = std::time::Instant::now();
	if level == BenchLevel::Slow {
		bench::run_staged_benchmark(
			&mut records, &categories, &config, &doh_clients,
		).await?;
	} else {
		bench::run_benchmark(
			&mut records, &categories, &config, &doh_clients,
		).await?;
	}
	phase_timings.push(("Benchmark", bench_start.elapsed(), None));

	// Filter out resolvers with <50% success rate (too noisy to report)
	let before_count = records.len();
	records.retain(|r| {
		r.benchmark.as_ref().map(|bm| bm.success_rate >= 50.0).unwrap_or(false)
	});
	let low_success_count = before_count - records.len();
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
		let before_count = records.len();
		records.retain(|r| {
			r.benchmark.as_ref()
				.and_then(|bm| bm.categories.get(cat_name))
				.map(|s| s.p50_ms <= config.max_resolver_ms)
				.unwrap_or(true)
		});
		let filtered_count = before_count - records.len();
		if filtered_count > 0 {
			println!(
				"Filtered {} resolver(s) with {} p50 > {} ms",
				filtered_count, cat_name, config.max_resolver_ms as u64,
			);
		}
	}

	// Pin system resolvers to top of records
	let (mut pinned, mut rest): (Vec<_>, Vec<_>) = records
		.into_iter()
		.partition(|r| r.resolver.is_system);
	// Preserve sort order within each group
	pinned.append(&mut rest);
	records = pinned;

	// Re-rank after filtering and pinning
	for (i, r) in records.iter_mut().enumerate() {
		if let Some(ref mut bm) = r.benchmark {
			bm.rank = i + 1;
			bm.tie_group = None;
		}
	}

	// Log final records to telemetry with full per-category breakdown
	for r in &records {
		if let Some(ref bm) = r.benchmark {
			// Build JSON object with per-category stats
			let cat_entries: Vec<String> = bm.categories.iter()
				.map(|(name, stats)| {
					format!(
						r#""{}": {{"p50_ms":{:.1},"score":{:.1},"success":{},"total":{},"timeouts":{}}}"#,
						name, stats.p50_ms, stats.score, stats.success_count, stats.total_count, stats.timeout_count,
					)
				})
				.collect();
			let categories_json = format!("{{{}}}", cat_entries.join(","));
			config.telemetry.log_result_detail(
				bm.rank, &r.resolver.addr.ip().to_string(), &r.resolver.label,
				bm.overall_score, bm.success_rate, &categories_json,
			);
		}
	}

	// Print pipeline summary
	let final_count = records.len();
	config.telemetry.log_pipeline("final_results", final_count);
	output::print_pipeline_summary(
		initial_count, post_discovery_count, post_char_count, final_count,
	);

	// Print phase timing summary
	let total_elapsed = pipeline_start.elapsed();
	output::print_phase_timing(&phase_timings, total_elapsed);

	// Print results table and conclusions
	output::print_results_table(&records);
	output::print_conclusions(&records);

	// Write CSV if requested
	if let Some(path) = &cli.output {
		output::write_csv(path, &records)?;
	}

	// Save resolver list if requested
	if let Some(path) = &cli.save_resolvers {
		output::write_resolver_list(path, &records)?;
	}

	Ok(())
}
