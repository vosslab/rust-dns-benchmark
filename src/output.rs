use comfy_table::{Table, ContentArrangement, presets::UTF8_FULL};

use anyhow::Result;

use crate::stats::ScoredResolver;
use crate::transport::{BenchmarkConfig, ResolverConfig};

/// Print a summary of the benchmark configuration before running.
pub fn print_config_summary(
	resolvers: &[ResolverConfig],
	warm_count: usize,
	cold_count: usize,
	tld_count: usize,
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
	if config.query_tld {
		println!("TLD domains:    {}", tld_count);
	}
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
	if let Some(seed) = config.seed {
		println!("Seed:           {}", seed);
	}
	println!();
}

/// Print the benchmark results as a formatted table.
pub fn print_results_table(results: &[ScoredResolver], show_tld: bool) {
	let mut table = Table::new();
	table.load_preset(UTF8_FULL);
	table.set_content_arrangement(ContentArrangement::Dynamic);

	// Build header
	let mut header = vec![
		"Rank", "Resolver", "IP Address", "Score",
		"Warm p50", "Cold p50",
	];
	if show_tld {
		header.push("TLD p50");
	}
	header.push("Success %");
	header.push("NXDOMAIN");
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

		let nxdomain_str = if s.intercepts_nxdomain {
			"Intercepts".to_string()
		} else {
			"OK".to_string()
		};

		let mut row = vec![
			rank_str,
			s.label.clone(),
			s.addr.clone(),
			format!("{:.1}", s.overall_score),
			format!("{:.1} ms", s.warm.p50_ms),
			format!("{:.1} ms", s.cold.p50_ms),
		];
		if show_tld {
			if let Some(ref tld) = s.tld {
				row.push(format!("{:.1} ms", tld.p50_ms));
			} else {
				row.push("-".to_string());
			}
		}
		row.push(format!("{:.1}%", s.success_rate));
		row.push(nxdomain_str);

		table.add_row(row);
	}

	println!("\nBenchmark Results");
	println!("=================\n");
	println!("{table}");

	if has_ties {
		println!("\nNote: resolvers with shared rank (e.g. 1-3) are statistically tied.");
	}
}

/// Write benchmark results to a CSV file.
pub fn write_csv(path: &str, results: &[ScoredResolver], show_tld: bool) -> Result<()> {
	let mut writer = csv::Writer::from_path(path)?;

	// Build header
	let mut header = vec![
		"rank", "resolver", "ip_address", "overall_score",
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
	header.extend_from_slice(&[
		"success_rate", "intercepts_nxdomain", "tie_group",
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
		let intercepts_str = if s.intercepts_nxdomain { "true" } else { "false" };
		let tie_str = r.tie_group.clone().unwrap_or_default();
		row.push(format!("{:.1}", s.success_rate));
		row.push(intercepts_str.to_string());
		row.push(tie_str);

		writer.write_record(&row)?;
	}

	writer.flush()?;
	println!("\nResults written to: {}", path);
	Ok(())
}
