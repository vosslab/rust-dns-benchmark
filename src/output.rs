use std::collections::BTreeMap;
use comfy_table::{Table, ContentArrangement, Cell, Color, Attribute, presets::UTF8_FULL};

use anyhow::Result;
use std::io::Write;

use crate::record::ResolverRecord;
use crate::transport::{BenchmarkConfig, Resolver};

/// Pick a color for a latency or score value (lower is better).
fn latency_color(ms: f64) -> Color {
	if ms < 30.0 {
		Color::Green
	} else if ms < 100.0 {
		Color::Yellow
	} else {
		Color::Red
	}
}

/// Pick a color for success rate percentage (higher is better).
fn success_color(pct: f64) -> Color {
	if pct >= 99.0 {
		Color::Green
	} else if pct >= 90.0 {
		Color::Yellow
	} else {
		Color::Red
	}
}

/// Print a summary of the benchmark configuration before running.
///
/// Displays three clearly separated sections:
/// 1. Resolvers under test (DNS servers being benchmarked)
/// 2. Query domains (websites queried against each resolver)
/// 3. Timing and options (benchmark parameters)
pub fn print_config_summary(
	resolvers: &[Resolver],
	categories: &BTreeMap<String, Vec<String>>,
	config: &BenchmarkConfig,
) {
	// Section 1: Resolvers under test
	println!("DNS Benchmark");
	println!("=============");
	println!("Resolvers under test: {}", resolvers.len());
	if resolvers.len() <= 20 {
		for r in resolvers {
			println!("  - {} ({})", r.label, r.addr);
		}
	} else {
		// Show first 5 and last 2 to keep output manageable
		for r in resolvers.iter().take(5) {
			println!("  - {} ({})", r.label, r.addr);
		}
		println!("  ... ({} more)", resolvers.len() - 7);
		for r in resolvers.iter().skip(resolvers.len() - 2) {
			println!("  - {} ({})", r.label, r.addr);
		}
	}

	// Section 2: Query domains (what we send to each resolver)
	println!();
	let total_domains: usize = categories.values().map(|v| v.len()).sum();
	println!("Query domains ({} total, sent to each resolver):", total_domains);
	for (category, domains) in categories {
		// Show a few example domains for context
		let examples: Vec<&str> = domains.iter().take(3).map(|s| s.as_str()).collect();
		let example_str = examples.join(", ");
		if domains.len() > 3 {
			println!("  {:<12} {:>3}  ({}, ...)", category, domains.len(), example_str);
		} else {
			println!("  {:<12} {:>3}  ({})", category, domains.len(), example_str);
		}
	}

	// Section 3: Timing and options, organized by phase
	let aaaa_label = if config.query_aaaa { "yes" } else { "no" };
	let dnssec_label = if config.dnssec { "yes" } else { "no" };
	let sort_label = match &config.sort_mode {
		crate::stats::SortMode::Score => "overall score".to_string(),
		crate::stats::SortMode::Category(name) => format!("{} p50", name),
		crate::stats::SortMode::Name => "name".to_string(),
	};

	println!();
	println!("Build:              {}", env!("BUILD_TIMESTAMP"));
	println!();
	println!("Options:");
	println!("  Level:            {}", config.level);
	println!("  Query AAAA:       {}", aaaa_label);
	println!("  DNSSEC (DO):      {}", dnssec_label);
	println!("  Sort by:          {}", sort_label);
	println!("  Pin system:       yes");
	if let Some(seed) = config.seed {
		println!("  Seed:             {}", seed);
	}

	if config.discover {
		println!();
		println!("Discovery phase:");
		println!("  UDP timeout:      {} ms", crate::bench::SCREEN_TIMEOUT_MS);
		println!("  TLS timeout:      {} ms", crate::bench::SCREEN_TLS_TIMEOUT_MS);
		println!("  Concurrency:      {}", crate::bench::DISCOVERY_CONCURRENCY.max(config.max_inflight));
	}

	println!();
	println!("Characterization phase:");
	println!("  Timeout:          {} ms", crate::transport::DEFAULT_CHAR_TIMEOUT_MS);
	println!("  Attempts:         {}", crate::transport::DEFAULT_CHAR_ATTEMPTS);

	if config.level == crate::cli::BenchLevel::Medium {
		println!();
		println!("Qualification phase:");
		println!("  Budget:           {}", crate::transport::DEFAULT_MEDIUM_BUDGET);
	}

	println!();
	println!("Benchmark phase:");
	println!("  Rounds:           {}", config.rounds);
	println!("  Timeout:          {} ms", config.timeout.as_millis());
	println!("  Concurrency:      {}", config.max_inflight);
	println!("  Spacing:          {} ms", config.inter_query_spacing.as_millis());
	println!();
}

/// Collect the ordered list of category names present in results.
fn result_category_names(results: &[ResolverRecord]) -> Vec<String> {
	let mut names: BTreeMap<String, ()> = BTreeMap::new();
	for r in results {
		if let Some(ref bm) = r.benchmark {
			for key in bm.categories.keys() {
				names.entry(key.clone()).or_default();
			}
		}
	}
	names.into_keys().collect()
}

/// Print the benchmark results as a formatted table with color coding.
pub fn print_results_table(results: &[ResolverRecord]) {
	let category_names = result_category_names(results);

	let mut table = Table::new();
	table.load_preset(UTF8_FULL);
	table.set_content_arrangement(ContentArrangement::Dynamic);

	// Check if any resolvers use non-UDP transport
	let has_mixed_transport = results.iter()
		.any(|r| r.resolver.transport.to_string() != "UDP");

	// Build header dynamically
	let mut header: Vec<String> = vec![
		"Rank".to_string(), "Resolver".to_string(), "IP Address".to_string(),
	];
	if has_mixed_transport {
		header.push("Proto".to_string());
	}
	header.push("Score".to_string());
	// Add a p50 column for each category
	for cat in &category_names {
		header.push(format!("{} p50", cat));
	}
	header.push("Success %".to_string());
	header.push("NXDOMAIN".to_string());
	header.push("DNSSEC".to_string());
	header.push("Rebind".to_string());

	let header_cells: Vec<Cell> = header.iter().map(|h| Cell::new(h)).collect();
	table.set_header(header_cells);

	let mut has_ties = false;
	for r in results {
		let bm = match &r.benchmark {
			Some(bm) => bm,
			None => continue,
		};

		// Rank display: show tie group label if tied
		let rank_str = match &bm.tie_group {
			Some(group) => {
				has_ties = true;
				group.clone()
			}
			None => format!("{}", bm.rank),
		};

		// Color the rank cell based on position
		let rank_cell = if bm.rank <= 3 {
			Cell::new(rank_str).fg(Color::Green).add_attribute(Attribute::Bold)
		} else if bm.rank <= 10 {
			Cell::new(rank_str).add_attribute(Attribute::Bold)
		} else {
			Cell::new(rank_str)
		};

		// NXDOMAIN status with color
		let nxdomain_cell = if r.intercepts_nxdomain() {
			Cell::new("Intercepts").fg(Color::Red)
		} else {
			Cell::new("OK").fg(Color::Green)
		};

		// Build label with optional system marker and PTR name
		let mut label = r.resolver.label.clone();
		if let Some(ref ptr) = r.resolver.ptr_name {
			// Only show PTR if it differs from the label
			if ptr != &r.resolver.label {
				label = format!("{} ({})", label, ptr);
			}
		}
		if r.resolver.is_system {
			label = format!("{} [sys]", label);
		}

		// Build row with colored cells
		let mut row: Vec<Cell> = vec![
			rank_cell,
			Cell::new(label),
			Cell::new(r.resolver.addr.ip().to_string()),
		];
		if has_mixed_transport {
			row.push(Cell::new(r.resolver.transport.to_string()));
		}

		// Score cell with color
		let score_text = format!("{:.1}", bm.overall_score);
		row.push(Cell::new(&score_text).fg(latency_color(bm.overall_score)));

		// Category p50 columns
		for cat in &category_names {
			if let Some(cat_stats) = bm.categories.get(cat) {
				let text = format!("{:.1} ms", cat_stats.p50_ms);
				row.push(Cell::new(&text).fg(latency_color(cat_stats.p50_ms)));
			} else {
				row.push(Cell::new("-"));
			}
		}

		// Success rate with color
		let success_text = format!("{:.1}%", bm.success_rate);
		row.push(Cell::new(&success_text).fg(success_color(bm.success_rate)));

		row.push(nxdomain_cell);

		// DNSSEC cell with color
		let dnssec_cell = match r.validates_dnssec() {
			Some(true) => Cell::new("Yes").fg(Color::Green),
			Some(false) => Cell::new("No"),
			None => Cell::new("-").fg(Color::DarkGrey),
		};
		row.push(dnssec_cell);

		// Rebinding protection cell with color
		let rebind_cell = match r.rebinding_protection() {
			Some(true) => Cell::new("Yes").fg(Color::Green),
			Some(false) => Cell::new("No"),
			None => Cell::new("-").fg(Color::DarkGrey),
		};
		row.push(rebind_cell);

		table.add_row(row);
	}

	println!("\nBenchmark Results");
	println!("=================\n");
	println!("{table}");

	if has_ties {
		println!("\nNote: resolvers with shared rank (e.g. 1-3) are statistically tied.");
	}

	// Footnote when system resolvers are pinned to the top
	let has_pinned = results.iter().any(|r| r.resolver.is_system);
	if has_pinned {
		println!("\nNote: system resolvers are pinned to the top of the displayed list");
		println!("and may not have the lowest benchmark score.");
	}
}

/// Print a summary of how many resolvers survived each pipeline stage.
pub fn print_pipeline_summary(
	initial: usize,
	post_discovery: usize,
	post_char: usize,
	final_count: usize,
) {
	println!("\nResolver Pipeline");
	println!("-----------------");
	println!("  Started:              {}", initial);
	if post_discovery != initial {
		println!("  After discovery:      {}", post_discovery);
	}
	if post_char != post_discovery {
		println!("  After characterization: {}", post_char);
	}
	println!("  Final results:        {}", final_count);
}

/// Print a compact phase-by-phase timing breakdown.
pub fn print_phase_timing(
	phases: &[(&str, std::time::Duration, Option<(usize, usize)>)],
	total: std::time::Duration,
) {
	println!("\nPhase Timing");
	println!("------------");
	for (name, dur, counts) in phases {
		let secs = dur.as_secs();
		let time_str = if secs >= 60 {
			format!("{}m {}s", secs / 60, secs % 60)
		} else {
			format!("{}s", secs)
		};
		// Right-pad phase name and left-pad time for alignment
		let count_str = match counts {
			Some((before, after)) => format!("  ({} -> {} resolvers)", before, after),
			None => String::new(),
		};
		println!("  {:<20} {:>8}{}", name, time_str, count_str);
	}
	let total_secs = total.as_secs();
	let total_str = if total_secs >= 60 {
		format!("{}m {}s", total_secs / 60, total_secs % 60)
	} else {
		format!("{}s", total_secs)
	};
	println!("  {:<20} {:>8}", "Total", total_str);
}

/// Print heuristic conclusions about the benchmark results.
pub fn print_conclusions(results: &[ResolverRecord]) {
	if results.is_empty() {
		return;
	}
	println!("\nConclusions");
	println!("===========\n");

	// Find the resolver with the true lowest benchmark score
	let best = results.iter()
		.filter_map(|r| r.benchmark.as_ref().map(|bm| (r, bm.overall_score)))
		.min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
		.map(|(r, _)| r);
	let best = match best {
		Some(r) => r,
		None => return,
	};
	let best_score = best.benchmark.as_ref().map(|b| b.overall_score).unwrap_or(f64::INFINITY);
	println!("Best benchmark score: {} (score {:.1})", best.resolver.label, best_score);

	// Report on system resolvers
	let total = results.len();
	for r in results {
		if !r.resolver.is_system {
			continue;
		}
		let bm = match &r.benchmark {
			Some(bm) => bm,
			None => continue,
		};
		// Note pinning if system resolver is displayed at a different rank than its score warrants
		if r.resolver.label != best.resolver.label {
			println!(
				"System resolver: {} ranked #{} in displayed results due to pinning.",
				r.resolver.label, bm.rank,
			);
		} else {
			println!(
				"Your system resolver {} ranked #{} out of {} tested.",
				r.resolver.label, bm.rank, total,
			);
		}
		// Compare to best
		if bm.overall_score > best_score && best_score > 0.0 {
			let pct_slower = ((bm.overall_score - best_score) / best_score) * 100.0;
			if pct_slower > 20.0 {
				println!(
					"  Switching to {} could improve DNS performance by ~{:.0}%.",
					best.resolver.label, pct_slower,
				);
			}
		}
		// Warn about NXDOMAIN interception on system resolver
		if r.intercepts_nxdomain() {
			println!(
				"  Warning: {} intercepts NXDOMAIN queries (ad-redirect behavior).",
				r.resolver.label,
			);
		}
		// Warn about missing DNSSEC validation
		if r.validates_dnssec() == Some(false) {
			println!(
				"  Warning: {} does not validate DNSSEC signatures.",
				r.resolver.label,
			);
		}
	}

	// Warn if all resolvers are slow (check first category as proxy)
	let first_cat = result_category_names(results).into_iter().next();
	if let Some(cat_name) = first_cat {
		let all_slow = results.iter().all(|r| {
			r.benchmark.as_ref()
				.and_then(|bm| bm.categories.get(&cat_name))
				.map(|s| s.p50_ms > 100.0)
				.unwrap_or(true)
		});
		if all_slow {
			println!("  Warning: all tested resolvers have {} p50 > 100 ms. Your network may have high latency.", cat_name);
		}
	}

	// IPv4 vs IPv6 comparison for same-provider pairs
	let first_cat_name = result_category_names(results).into_iter().next();
	let mut pairs_printed = false;
	for r in results {
		let bm = match &r.benchmark { Some(bm) => bm, None => continue };
		// Look for a matching -v6 suffix entry
		let base_label = r.resolver.label.trim_end_matches("-v6");
		if base_label == r.resolver.label {
			// This is the IPv4 entry; look for the v6 pair
			let v6_label = format!("{}-v6", r.resolver.label);
			if let Some(v6) = results.iter().find(|x| x.resolver.label == v6_label) {
				let v6_bm = match &v6.benchmark { Some(bm) => bm, None => continue };
				if !pairs_printed {
					println!("\nIPv4 vs IPv6 Comparison");
					println!("----------------------");
					pairs_printed = true;
				}
				let diff_pct = if bm.overall_score > 0.0 {
					((v6_bm.overall_score - bm.overall_score) / bm.overall_score) * 100.0
				} else {
					0.0
				};
				let direction = if diff_pct > 0.0 { "slower" } else { "faster" };
				// Use first category p50 for the comparison display
				if let Some(ref cat) = first_cat_name {
					let v4_p50 = bm.categories.get(cat).map(|s| s.p50_ms).unwrap_or(0.0);
					let v6_p50 = v6_bm.categories.get(cat).map(|s| s.p50_ms).unwrap_or(0.0);
					println!("  {} IPv4: {:.1} ms vs IPv6: {:.1} ms ({:.0}% {})",
						base_label, v4_p50, v6_p50, diff_pct.abs(), direction);
				}
			}
		}
	}
}

/// Write benchmark results to a CSV file.
pub fn write_csv(path: &str, results: &[ResolverRecord]) -> Result<()> {
	let category_names = result_category_names(results);
	let mut writer = csv::Writer::from_path(path)?;

	// Build header dynamically
	let mut header: Vec<String> = vec![
		"rank".to_string(), "resolver".to_string(), "ip_address".to_string(),
		"transport".to_string(), "overall_score".to_string(),
	];
	// Add 8 columns per category (p50, p95, mean, stddev, success, timeout, total, score)
	for cat in &category_names {
		header.push(format!("{}_p50_ms", cat));
		header.push(format!("{}_p95_ms", cat));
		header.push(format!("{}_mean_ms", cat));
		header.push(format!("{}_stddev_ms", cat));
		header.push(format!("{}_success", cat));
		header.push(format!("{}_timeout", cat));
		header.push(format!("{}_total", cat));
		header.push(format!("{}_score", cat));
	}
	header.extend_from_slice(&[
		"success_rate".to_string(), "intercepts_nxdomain".to_string(),
		"validates_dnssec".to_string(), "rebinding_protection".to_string(),
		"ptr_name".to_string(), "tie_group".to_string(),
	]);
	writer.write_record(&header)?;

	for r in results {
		let bm = match &r.benchmark { Some(bm) => bm, None => continue };
		let rank_str = match &bm.tie_group {
			Some(group) => group.clone(),
			None => bm.rank.to_string(),
		};

		let mut row = vec![
			rank_str,
			r.resolver.label.clone(),
			r.resolver.addr.ip().to_string(),
			r.resolver.transport.to_string(),
			format!("{:.2}", bm.overall_score),
		];

		// Category columns
		for cat in &category_names {
			if let Some(cs) = bm.categories.get(cat) {
				row.extend_from_slice(&[
					format!("{:.2}", cs.p50_ms),
					format!("{:.2}", cs.p95_ms),
					format!("{:.2}", cs.mean_ms),
					format!("{:.2}", cs.stddev_ms),
					cs.success_count.to_string(),
					cs.timeout_count.to_string(),
					cs.total_count.to_string(),
					format!("{:.2}", cs.score),
				]);
			} else {
				// Empty columns for missing category
				row.extend_from_slice(&[
					String::new(), String::new(), String::new(), String::new(),
					String::new(), String::new(), String::new(), String::new(),
				]);
			}
		}

		let intercepts_str = if r.intercepts_nxdomain() { "true" } else { "false" };
		let dnssec_csv = match r.validates_dnssec() {
			Some(true) => "true", Some(false) => "false", None => "",
		};
		let rebind_csv = match r.rebinding_protection() {
			Some(true) => "true", Some(false) => "false", None => "",
		};
		let ptr_str = r.resolver.ptr_name.clone().unwrap_or_default();
		let tie_str = bm.tie_group.clone().unwrap_or_default();
		row.push(format!("{:.1}", bm.success_rate));
		row.push(intercepts_str.to_string());
		row.push(dnssec_csv.to_string());
		row.push(rebind_csv.to_string());
		row.push(ptr_str);
		row.push(tie_str);

		writer.write_record(&row)?;
	}

	writer.flush()?;
	println!("\nResults written to: {}", path);
	Ok(())
}

/// Save surviving resolver addresses to a file (one per line, IP  # Label).
pub fn write_resolver_list(path: &str, results: &[ResolverRecord]) -> Result<()> {
	let mut file = std::fs::File::create(path)?;
	writeln!(file, "# DNS Benchmark - surviving resolvers (ranked by performance)")?;
	for r in results {
		// Write in resolver file format: address  # Label
		writeln!(file, "{}  # {}", r.resolver.addr.ip(), r.resolver.label)?;
	}
	println!("\nResolver list written to: {}", path);
	Ok(())
}
