use comfy_table::{Table, ContentArrangement, presets::UTF8_FULL};

use anyhow::Result;

use crate::stats::ScoredResolver;
use crate::transport::{BenchmarkConfig, ResolverConfig};

/// Print a summary of the benchmark configuration before running.
pub fn print_config_summary(
	resolvers: &[ResolverConfig],
	warm_count: usize,
	cold_count: usize,
	config: &BenchmarkConfig,
) {
	println!("DNS Benchmark Configuration");
	println!("===========================");
	println!("Resolvers:      {}", resolvers.len());
	for r in resolvers {
		println!("  - {} ({})", r.label, r.addr);
	}
	println!("Warm domains:   {}", warm_count);
	println!("Cold domains:   {}", cold_count);
	println!("Rounds:         {}", config.rounds);
	println!("Timeout:        {} ms", config.timeout.as_millis());
	println!("Concurrency:    {}", config.max_inflight);
	println!("Spacing:        {} ms", config.inter_query_spacing.as_millis());
	let aaaa_label = if config.query_aaaa { "yes" } else { "no" };
	println!("Query AAAA:     {}", aaaa_label);
	if let Some(seed) = config.seed {
		println!("Seed:           {}", seed);
	}
	println!();
}

/// Print the benchmark results as a formatted table.
pub fn print_results_table(results: &[ScoredResolver]) {
	let mut table = Table::new();
	table.load_preset(UTF8_FULL);
	table.set_content_arrangement(ContentArrangement::Dynamic);
	table.set_header(vec![
		"Rank", "Resolver", "Score",
		"Warm p50", "Warm p95",
		"Cold p50", "Cold p95",
		"Success %",
	]);

	for r in results {
		let s = &r.stats;
		table.add_row(vec![
			format!("{}", r.rank),
			s.label.clone(),
			format!("{:.1}", s.overall_score),
			format!("{:.1} ms", s.warm.p50_ms),
			format!("{:.1} ms", s.warm.p95_ms),
			format!("{:.1} ms", s.cold.p50_ms),
			format!("{:.1} ms", s.cold.p95_ms),
			format!("{:.1}%", s.success_rate),
		]);
	}

	println!("\nBenchmark Results");
	println!("=================\n");
	println!("{table}");
}

/// Write benchmark results to a CSV file.
pub fn write_csv(path: &str, results: &[ScoredResolver]) -> Result<()> {
	let mut writer = csv::Writer::from_path(path)?;

	// Write header
	writer.write_record([
		"rank", "resolver", "overall_score",
		"warm_p50_ms", "warm_p95_ms", "warm_mean_ms", "warm_stddev_ms",
		"warm_success", "warm_timeout", "warm_total", "warm_score",
		"cold_p50_ms", "cold_p95_ms", "cold_mean_ms", "cold_stddev_ms",
		"cold_success", "cold_timeout", "cold_total", "cold_score",
		"success_rate",
	])?;

	for r in results {
		let s = &r.stats;
		writer.write_record([
			r.rank.to_string(),
			s.label.clone(),
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
			format!("{:.1}", s.success_rate),
		])?;
	}

	writer.flush()?;
	println!("\nResults written to: {}", path);
	Ok(())
}
