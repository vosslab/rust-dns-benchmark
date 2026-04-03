use comfy_table::{Table, ContentArrangement, Cell, Color, Attribute, presets::UTF8_FULL};

use anyhow::Result;
use std::io::Write;

use crate::stats::ScoredResolver;
use crate::transport::{BenchmarkConfig, ResolverConfig};

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
pub fn print_config_summary(
	resolvers: &[ResolverConfig],
	warm_count: usize,
	cold_count: usize,
	tld_count: usize,
	dotcom_count: usize,
	dnssec_count: usize,
	config: &BenchmarkConfig,
) {
	println!("DNS Benchmark Configuration");
	println!("===========================");
	println!("Resolvers:      {}", resolvers.len());
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
	println!("Warm domains:   {}", warm_count);
	println!("Cold domains:   {}", cold_count);
	println!("TLD domains:    {}", tld_count);
	println!("Dotcom domains: {}", dotcom_count);
	if config.query_dnssec_domains {
		println!("DNSSEC domains: {}", dnssec_count);
	}
	println!("Char timeout:   {} ms", crate::transport::DEFAULT_CHAR_TIMEOUT_MS);
	println!("Char attempts:  {}", crate::transport::DEFAULT_CHAR_ATTEMPTS);
	println!("Rounds:         {}", config.rounds);
	println!("Timeout:        {} ms", config.timeout.as_millis());
	println!("Concurrency:    {}", config.max_inflight);
	println!("Spacing:        {} ms", config.inter_query_spacing.as_millis());
	let aaaa_label = if config.query_aaaa { "yes" } else { "no" };
	println!("Query AAAA:     {}", aaaa_label);
	let dnssec_label = if config.dnssec { "yes" } else { "no" };
	println!("DNSSEC (DO):    {}", dnssec_label);
	if config.discover {
		println!("Discovery:      top {}", config.top_n);
	}
	let sort_label = match config.sort_mode {
		crate::stats::SortMode::Score => "overall score",
		crate::stats::SortMode::Warm => "warm (cached) p50",
		crate::stats::SortMode::Cold => "cold (uncached) p50",
		crate::stats::SortMode::Tld => "TLD p50",
		crate::stats::SortMode::Dotcom => "dotcom p50",
		crate::stats::SortMode::Name => "name",
	};
	println!("Sort by:        {}", sort_label);
	println!("Pin system:     yes");
	if let Some(seed) = config.seed {
		println!("Seed:           {}", seed);
	}
	println!();
}

/// Print the benchmark results as a formatted table with color coding.
pub fn print_results_table(results: &[ScoredResolver], show_tld: bool, show_dotcom: bool, show_dnssec: bool) {
	let mut table = Table::new();
	table.load_preset(UTF8_FULL);
	table.set_content_arrangement(ContentArrangement::Dynamic);

	// Check if any resolvers use non-UDP transport
	let has_mixed_transport = results.iter()
		.any(|r| r.stats.transport != "UDP");

	// Build header
	let mut header = vec![
		"Rank", "Resolver", "IP Address",
	];
	if has_mixed_transport {
		header.push("Proto");
	}
	header.extend_from_slice(&["Score", "Warm p50", "Cold p50"]);
	if show_tld {
		header.push("TLD p50");
	}
	if show_dotcom {
		header.push("DotCom p50");
	}
	if show_dnssec {
		header.push("DNSSEC p50");
	}
	header.push("Success %");
	header.push("NXDOMAIN");
	header.push("DNSSEC");
	header.push("Rebind");
	table.set_header(header);

	let mut has_ties = false;
	for r in results {
		let s = &r.stats;

		// Rank display: show tie group label if tied
		let rank_str = match &r.tie_group {
			Some(group) => {
				has_ties = true;
				group.clone()
			}
			None => format!("{}", r.rank),
		};

		// Color the rank cell based on position
		let rank_cell = if r.rank <= 3 {
			Cell::new(rank_str).fg(Color::Green).add_attribute(Attribute::Bold)
		} else if r.rank <= 10 {
			Cell::new(rank_str).add_attribute(Attribute::Bold)
		} else {
			Cell::new(rank_str)
		};

		// NXDOMAIN status with color
		let nxdomain_cell = if s.intercepts_nxdomain {
			Cell::new("Intercepts").fg(Color::Red)
		} else {
			Cell::new("OK").fg(Color::Green)
		};

		// Build label with optional system marker and PTR name
		let mut label = s.label.clone();
		if let Some(ref ptr) = s.ptr_name {
			// Only show PTR if it differs from the label
			if ptr != &s.label {
				label = format!("{} ({})", label, ptr);
			}
		}
		if r.is_system {
			label = format!("{} [sys]", label);
		}

		// Build row with colored cells
		let mut row: Vec<Cell> = vec![
			rank_cell,
			Cell::new(label),
			Cell::new(s.addr.clone()),
		];
		if has_mixed_transport {
			row.push(Cell::new(s.transport.clone()));
		}

		// Score and latency cells with color
		let score_text = format!("{:.1}", s.overall_score);
		row.push(Cell::new(&score_text).fg(latency_color(s.overall_score)));

		let warm_text = format!("{:.1} ms", s.warm.p50_ms);
		row.push(Cell::new(&warm_text).fg(latency_color(s.warm.p50_ms)));

		let cold_text = format!("{:.1} ms", s.cold.p50_ms);
		row.push(Cell::new(&cold_text).fg(latency_color(s.cold.p50_ms)));

		if show_tld {
			if let Some(ref tld) = s.tld {
				let tld_text = format!("{:.1} ms", tld.p50_ms);
				row.push(Cell::new(&tld_text).fg(latency_color(tld.p50_ms)));
			} else {
				row.push(Cell::new("-"));
			}
		}

		if show_dotcom {
			if let Some(ref dc) = s.dotcom {
				let dc_text = format!("{:.1} ms", dc.p50_ms);
				row.push(Cell::new(&dc_text).fg(latency_color(dc.p50_ms)));
			} else {
				row.push(Cell::new("-"));
			}
		}

		if show_dnssec {
			if let Some(ref ds) = s.dnssec_bench {
				let ds_text = format!("{:.1} ms", ds.p50_ms);
				row.push(Cell::new(&ds_text).fg(latency_color(ds.p50_ms)));
			} else {
				row.push(Cell::new("-"));
			}
		}

		// Success rate with color
		let success_text = format!("{:.1}%", s.success_rate);
		row.push(Cell::new(&success_text).fg(success_color(s.success_rate)));

		row.push(nxdomain_cell);

		// DNSSEC cell with color
		let dnssec_cell = match s.validates_dnssec {
			Some(true) => Cell::new("Yes").fg(Color::Green),
			Some(false) => Cell::new("No"),
			None => Cell::new("-").fg(Color::DarkGrey),
		};
		row.push(dnssec_cell);

		// Rebinding protection cell with color
		let rebind_cell = match s.rebinding_protection {
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
}

/// Print a summary of how many resolvers survived each pipeline stage.
pub fn print_pipeline_summary(
	initial: usize,
	post_discovery: usize,
	post_char: usize,
	final_count: usize,
	top_n: usize,
) {
	println!("\nResolver Pipeline");
	println!("-----------------");
	println!("  Started:              {}", initial);
	if post_discovery != initial {
		println!("  After discovery:      {} (--top {} filter applied)", post_discovery, top_n);
	}
	if post_char != post_discovery {
		println!("  After characterization: {}", post_char);
	}
	println!("  Final results:        {}", final_count);
}

/// Print heuristic conclusions about the benchmark results.
pub fn print_conclusions(results: &[ScoredResolver]) {
	if results.is_empty() {
		return;
	}
	println!("\nConclusions");
	println!("===========\n");

	// Find the best resolver overall
	let best = &results[0];
	println!("Fastest resolver: {} (score {:.1})", best.stats.label, best.stats.overall_score);

	// Report on system resolvers
	let total = results.len();
	for r in results {
		if !r.is_system {
			continue;
		}
		println!(
			"Your system resolver {} ranked #{} out of {} tested.",
			r.stats.label, r.rank, total,
		);
		// Compare to best
		if r.rank > 1 && best.stats.overall_score > 0.0 {
			let pct_slower = ((r.stats.overall_score - best.stats.overall_score)
				/ best.stats.overall_score) * 100.0;
			if pct_slower > 20.0 {
				println!(
					"  Switching to {} could improve DNS performance by ~{:.0}%.",
					best.stats.label, pct_slower,
				);
			}
		}
		// Warn about NXDOMAIN interception on system resolver
		if r.stats.intercepts_nxdomain {
			println!(
				"  Warning: {} intercepts NXDOMAIN queries (ad-redirect behavior).",
				r.stats.label,
			);
		}
		// Warn about missing DNSSEC validation
		if r.stats.validates_dnssec == Some(false) {
			println!(
				"  Warning: {} does not validate DNSSEC signatures.",
				r.stats.label,
			);
		}
	}

	// Warn if all resolvers are slow
	let all_slow = results.iter().all(|r| r.stats.warm.p50_ms > 100.0);
	if all_slow {
		println!("  Warning: all tested resolvers have warm p50 > 100 ms. Your network may have high latency.");
	}

	// IPv4 vs IPv6 comparison for same-provider pairs
	let mut pairs_printed = false;
	for r in results {
		// Look for a matching -v6 suffix entry
		let base_label = r.stats.label.trim_end_matches("-v6");
		if base_label == r.stats.label {
			// This is the IPv4 entry; look for the v6 pair
			let v6_label = format!("{}-v6", r.stats.label);
			if let Some(v6) = results.iter().find(|x| x.stats.label == v6_label) {
				if !pairs_printed {
					println!("\nIPv4 vs IPv6 Comparison");
					println!("----------------------");
					pairs_printed = true;
				}
				let diff_pct = if r.stats.overall_score > 0.0 {
					((v6.stats.overall_score - r.stats.overall_score) / r.stats.overall_score) * 100.0
				} else {
					0.0
				};
				let direction = if diff_pct > 0.0 { "slower" } else { "faster" };
				println!("  {} IPv4: {:.1} ms vs IPv6: {:.1} ms ({:.0}% {})",
					base_label, r.stats.warm.p50_ms, v6.stats.warm.p50_ms,
					diff_pct.abs(), direction);
			}
		}
	}
}

/// Write benchmark results to a CSV file.
pub fn write_csv(path: &str, results: &[ScoredResolver], show_tld: bool, show_dotcom: bool, show_dnssec: bool) -> Result<()> {
	let mut writer = csv::Writer::from_path(path)?;

	// Build header
	let mut header = vec![
		"rank", "resolver", "ip_address", "transport", "overall_score",
		"warm_p50_ms", "warm_p95_ms", "warm_mean_ms", "warm_stddev_ms",
		"warm_success", "warm_timeout", "warm_total", "warm_score",
		"cold_p50_ms", "cold_p95_ms", "cold_mean_ms", "cold_stddev_ms",
		"cold_success", "cold_timeout", "cold_total", "cold_score",
	];
	if show_tld {
		header.extend_from_slice(&[
			"tld_p50_ms", "tld_p95_ms", "tld_mean_ms", "tld_stddev_ms",
			"tld_success", "tld_timeout", "tld_total", "tld_score",
		]);
	}
	if show_dotcom {
		header.extend_from_slice(&[
			"dotcom_p50_ms", "dotcom_p95_ms", "dotcom_mean_ms", "dotcom_stddev_ms",
			"dotcom_success", "dotcom_timeout", "dotcom_total", "dotcom_score",
		]);
	}
	if show_dnssec {
		header.extend_from_slice(&[
			"dnssec_p50_ms", "dnssec_p95_ms", "dnssec_mean_ms", "dnssec_stddev_ms",
			"dnssec_success", "dnssec_timeout", "dnssec_total", "dnssec_score",
		]);
	}
	header.extend_from_slice(&[
		"success_rate", "intercepts_nxdomain", "validates_dnssec",
		"rebinding_protection", "ptr_name", "tie_group",
	]);
	writer.write_record(&header)?;

	for r in results {
		let s = &r.stats;
		let rank_str = match &r.tie_group {
			Some(group) => group.clone(),
			None => r.rank.to_string(),
		};

		let mut row = vec![
			rank_str,
			s.label.clone(),
			s.addr.clone(),
			s.transport.clone(),
			format!("{:.2}", s.overall_score),
			format!("{:.2}", s.warm.p50_ms),
			format!("{:.2}", s.warm.p95_ms),
			format!("{:.2}", s.warm.mean_ms),
			format!("{:.2}", s.warm.stddev_ms),
			s.warm.success_count.to_string(),
			s.warm.timeout_count.to_string(),
			s.warm.total_count.to_string(),
			format!("{:.2}", s.warm.score),
			format!("{:.2}", s.cold.p50_ms),
			format!("{:.2}", s.cold.p95_ms),
			format!("{:.2}", s.cold.mean_ms),
			format!("{:.2}", s.cold.stddev_ms),
			s.cold.success_count.to_string(),
			s.cold.timeout_count.to_string(),
			s.cold.total_count.to_string(),
			format!("{:.2}", s.cold.score),
		];
		if show_tld {
			if let Some(ref tld) = s.tld {
				row.extend_from_slice(&[
					format!("{:.2}", tld.p50_ms),
					format!("{:.2}", tld.p95_ms),
					format!("{:.2}", tld.mean_ms),
					format!("{:.2}", tld.stddev_ms),
					tld.success_count.to_string(),
					tld.timeout_count.to_string(),
					tld.total_count.to_string(),
					format!("{:.2}", tld.score),
				]);
			} else {
				row.extend_from_slice(&[
					String::new(), String::new(), String::new(), String::new(),
					String::new(), String::new(), String::new(), String::new(),
				]);
			}
		}
		if show_dotcom {
			if let Some(ref dc) = s.dotcom {
				row.extend_from_slice(&[
					format!("{:.2}", dc.p50_ms),
					format!("{:.2}", dc.p95_ms),
					format!("{:.2}", dc.mean_ms),
					format!("{:.2}", dc.stddev_ms),
					dc.success_count.to_string(),
					dc.timeout_count.to_string(),
					dc.total_count.to_string(),
					format!("{:.2}", dc.score),
				]);
			} else {
				row.extend_from_slice(&[
					String::new(), String::new(), String::new(), String::new(),
					String::new(), String::new(), String::new(), String::new(),
				]);
			}
		}
		if show_dnssec {
			if let Some(ref ds) = s.dnssec_bench {
				row.extend_from_slice(&[
					format!("{:.2}", ds.p50_ms),
					format!("{:.2}", ds.p95_ms),
					format!("{:.2}", ds.mean_ms),
					format!("{:.2}", ds.stddev_ms),
					ds.success_count.to_string(),
					ds.timeout_count.to_string(),
					ds.total_count.to_string(),
					format!("{:.2}", ds.score),
				]);
			} else {
				row.extend_from_slice(&[
					String::new(), String::new(), String::new(), String::new(),
					String::new(), String::new(), String::new(), String::new(),
				]);
			}
		}
		let intercepts_str = if s.intercepts_nxdomain { "true" } else { "false" };
		let dnssec_csv = match s.validates_dnssec {
			Some(true) => "true", Some(false) => "false", None => "",
		};
		let rebind_csv = match s.rebinding_protection {
			Some(true) => "true", Some(false) => "false", None => "",
		};
		let ptr_str = s.ptr_name.clone().unwrap_or_default();
		let tie_str = r.tie_group.clone().unwrap_or_default();
		row.push(format!("{:.1}", s.success_rate));
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
pub fn write_resolver_list(path: &str, results: &[ScoredResolver]) -> Result<()> {
	let mut file = std::fs::File::create(path)?;
	writeln!(file, "# DNS Benchmark - surviving resolvers (ranked by performance)")?;
	for r in results {
		let s = &r.stats;
		// Write in resolver file format: address  # Label
		writeln!(file, "{}  # {}", s.addr, s.label)?;
	}
	println!("\nResolver list written to: {}", path);
	Ok(())
}
