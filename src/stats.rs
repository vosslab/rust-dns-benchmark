use std::collections::BTreeMap;

/// Sort mode for ranking resolvers
#[derive(Debug, Clone, Default)]
pub enum SortMode {
	/// Sort by overall composite score (default)
	#[default]
	Score,
	/// Sort by a specific category's p50 latency (e.g. "cached", "tld")
	Category(String),
	/// Sort alphabetically by resolver name
	Name,
}

/// Parse a sort mode string, returning Score, Name, or Category(name).
pub fn parse_sort_mode(s: &str) -> SortMode {
	match s {
		"score" => SortMode::Score,
		"name" => SortMode::Name,
		other => SortMode::Category(other.to_string()),
	}
}

/// Statistics for a set of queries (e.g. cached, uncached, tld, dotcom)
#[derive(Debug, Clone, Default)]
pub struct SetStats {
	pub p50_ms: f64,
	pub p95_ms: f64,
	pub mean_ms: f64,
	pub stddev_ms: f64,
	pub success_count: usize,
	pub timeout_count: usize,
	pub total_count: usize,
	pub score: f64,
}


/// Calculate the p-th percentile from a sorted slice using nearest-rank method.
///
/// Args:
///   sorted_values: Pre-sorted slice of f64 values.
///   p: Percentile between 0.0 and 100.0 (e.g. 50.0 for median).
///
/// Returns:
///   None if the slice is empty, otherwise the percentile value.
pub fn percentile(sorted_values: &[f64], p: f64) -> Option<f64> {
	if sorted_values.is_empty() {
		return None;
	}
	if sorted_values.len() == 1 {
		return Some(sorted_values[0]);
	}
	// Nearest-rank: rank = ceil(p/100 * N)
	let n = sorted_values.len();
	let rank = ((p / 100.0) * n as f64).ceil() as usize;
	// Clamp rank to valid index range [1, n]
	let rank = rank.clamp(1, n);
	Some(sorted_values[rank - 1])
}

/// Calculate the arithmetic mean of a slice of values.
pub fn mean(values: &[f64]) -> Option<f64> {
	if values.is_empty() {
		return None;
	}
	let sum: f64 = values.iter().sum();
	Some(sum / values.len() as f64)
}

/// Calculate the population standard deviation of a slice of values.
pub fn stddev(values: &[f64]) -> Option<f64> {
	let avg = mean(values)?;
	let variance = values.iter()
		.map(|v| (v - avg).powi(2))
		.sum::<f64>() / values.len() as f64;
	Some(variance.sqrt())
}

/// Calculate a set score that balances median latency, tail latency, and reliability.
///
/// Formula: p50 + 0.5 * (p95 - p50) + penalty_ms * timeout_rate
///
/// - p50: baseline latency (median)
/// - 0.5 * (p95 - p50): half-weighted tail penalty to penalize inconsistent resolvers
/// - penalty_ms * timeout_rate: reliability penalty using full timeout as the cost
pub fn set_score(stats: &SetStats, timeout_penalty_ms: f64) -> f64 {
	// Dead resolvers (no successful queries) get infinite score so they sort last
	if stats.success_count == 0 {
		return f64::INFINITY;
	}
	let timeout_rate = if stats.total_count > 0 {
		stats.timeout_count as f64 / stats.total_count as f64
	} else {
		0.0
	};
	// Composite: median + half the tail spread + timeout penalty
	stats.p50_ms + 0.5 * (stats.p95_ms - stats.p50_ms) + timeout_penalty_ms * timeout_rate
}

/// Compute SetStats from a slice of latencies (in milliseconds) and counts.
pub fn compute_set_stats(
	latencies_ms: &[f64],
	success_count: usize,
	timeout_count: usize,
	total_count: usize,
	timeout_penalty_ms: f64,
) -> SetStats {
	let mut sorted = latencies_ms.to_vec();
	sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

	let p50 = percentile(&sorted, 50.0).unwrap_or(0.0);
	let p95 = percentile(&sorted, 95.0).unwrap_or(0.0);
	let avg = mean(&sorted).unwrap_or(0.0);
	let sd = stddev(&sorted).unwrap_or(0.0);

	let mut stats = SetStats {
		p50_ms: p50,
		p95_ms: p95,
		mean_ms: avg,
		stddev_ms: sd,
		success_count,
		timeout_count,
		total_count,
		score: 0.0,
	};
	stats.score = set_score(&stats, timeout_penalty_ms);
	stats
}

/// Compute the uncertainty of a score using MAD (median absolute deviation).
///
/// Uses the scale factor 1.4826 for consistency with normal distribution.
/// Returns the uncertainty band half-width for the given latencies.
pub fn compute_uncertainty(latencies_ms: &[f64]) -> f64 {
	if latencies_ms.len() < 2 {
		return 0.0;
	}
	let mut sorted = latencies_ms.to_vec();
	sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

	let median = percentile(&sorted, 50.0).unwrap_or(0.0);

	// Compute absolute deviations from median
	let mut abs_devs: Vec<f64> = sorted.iter()
		.map(|v| (v - median).abs())
		.collect();
	abs_devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

	// MAD = median of absolute deviations
	let mad = percentile(&abs_devs, 50.0).unwrap_or(0.0);

	// Scale factor for normal distribution consistency
	1.4826 * mad
}

/// Detect ties among ranked resolver records based on overlapping uncertainty bands.
///
/// For consecutive pairs: if |score_a - score_b| < uncertainty_a + uncertainty_b,
/// they are tied. Groups tied resolvers and assigns shared rank labels.
pub fn detect_ties_on_records(records: &mut [crate::record::ResolverRecord], uncertainties: &[f64]) {
	if records.len() < 2 || uncertainties.len() != records.len() {
		return;
	}

	let n = records.len();
	let mut group_id: Vec<usize> = (0..n).collect();

	// Check consecutive pairs for overlap
	for i in 0..(n - 1) {
		let score_a = records[i].benchmark.as_ref().map(|b| b.overall_score).unwrap_or(f64::INFINITY);
		let score_b = records[i + 1].benchmark.as_ref().map(|b| b.overall_score).unwrap_or(f64::INFINITY);
		let diff = (score_a - score_b).abs();
		let threshold = uncertainties[i] + uncertainties[i + 1];

		if diff < threshold {
			let target = group_id[i];
			let source = group_id[i + 1];
			for g in group_id.iter_mut() {
				if *g == source {
					*g = target;
				}
			}
		}
	}

	// Convert group IDs to rank labels
	let mut i = 0;
	while i < n {
		let gid = group_id[i];
		let members: Vec<usize> = (0..n).filter(|&j| group_id[j] == gid).collect();

		if members.len() > 1 {
			let first_rank = members[0] + 1;
			let last_rank = members[members.len() - 1] + 1;
			let label = format!("{}-{}", first_rank, last_rank);
			for &m in &members {
				if let Some(ref mut bm) = records[m].benchmark {
					bm.tie_group = Some(label.clone());
				}
			}
		}

		i = members.last().map(|&l| l + 1).unwrap_or(i + 1);
	}
}

/// Rank resolver records by the chosen sort mode, ascending.
/// Sets benchmark.rank on each record. Lower scores/latencies are better.
pub fn rank_records(records: &mut [crate::record::ResolverRecord], sort_mode: &SortMode) {
	let cmp_f64 = |a: f64, b: f64| -> std::cmp::Ordering {
		a.partial_cmp(&b).unwrap_or(std::cmp::Ordering::Equal)
	};

	match sort_mode {
		SortMode::Score => {
			records.sort_by(|a, b| {
				let sa = a.benchmark.as_ref().map(|bm| bm.overall_score).unwrap_or(f64::INFINITY);
				let sb = b.benchmark.as_ref().map(|bm| bm.overall_score).unwrap_or(f64::INFINITY);
				cmp_f64(sa, sb)
			});
		}
		SortMode::Category(name) => {
			records.sort_by(|a, b| {
				let va = a.benchmark.as_ref().and_then(|bm| bm.categories.get(name)).map(|s| s.p50_ms).unwrap_or(f64::MAX);
				let vb = b.benchmark.as_ref().and_then(|bm| bm.categories.get(name)).map(|s| s.p50_ms).unwrap_or(f64::MAX);
				cmp_f64(va, vb)
			});
		}
		SortMode::Name => {
			records.sort_by(|a, b| a.resolver.label.to_lowercase().cmp(&b.resolver.label.to_lowercase()));
		}
	}
	// Set rank on each record's benchmark result
	for (i, rec) in records.iter_mut().enumerate() {
		if let Some(ref mut bm) = rec.benchmark {
			bm.rank = i + 1;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_percentile_basic() {
		let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];
		assert_eq!(percentile(&values, 50.0), Some(5.0));
		assert_eq!(percentile(&values, 95.0), Some(10.0));
		assert_eq!(percentile(&values, 10.0), Some(1.0));
	}

	#[test]
	fn test_percentile_empty() {
		let values: Vec<f64> = vec![];
		assert_eq!(percentile(&values, 50.0), None);
	}

	#[test]
	fn test_percentile_single() {
		let values = vec![42.0];
		assert_eq!(percentile(&values, 50.0), Some(42.0));
		assert_eq!(percentile(&values, 95.0), Some(42.0));
	}

	#[test]
	fn test_mean() {
		let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
		assert_eq!(mean(&values), Some(3.0));
	}

	#[test]
	fn test_stddev() {
		let values = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
		let sd = stddev(&values).unwrap();
		// Population stddev should be 2.0
		assert!((sd - 2.0).abs() < 0.01);
	}

	#[test]
	fn test_set_score_no_timeouts() {
		let stats = SetStats {
			p50_ms: 20.0,
			p95_ms: 50.0,
			mean_ms: 25.0,
			stddev_ms: 10.0,
			success_count: 100,
			timeout_count: 0,
			total_count: 100,
			score: 0.0,
		};
		// score = 20 + 0.5*(50-20) + 5000*0 = 20 + 15 = 35
		let score = set_score(&stats, 5000.0);
		assert!((score - 35.0).abs() < 0.01);
	}

	#[test]
	fn test_set_score_with_timeouts() {
		let stats = SetStats {
			p50_ms: 20.0,
			p95_ms: 50.0,
			mean_ms: 25.0,
			stddev_ms: 10.0,
			success_count: 90,
			timeout_count: 10,
			total_count: 100,
			score: 0.0,
		};
		// score = 20 + 0.5*(50-20) + 5000*0.1 = 20 + 15 + 500 = 535
		let score = set_score(&stats, 5000.0);
		assert!((score - 535.0).abs() < 0.01);
	}

	/// Helper to build a minimal ResolverRecord for testing
	fn make_test_record(label: &str, overall_score: f64, success_rate: f64) -> crate::record::ResolverRecord {
		use crate::transport::{Resolver, DnsTransport};
		let mut resolver = Resolver::new("0.0.0.0:53".parse().unwrap(), DnsTransport::Udp);
		resolver.label = label.to_string();
		let mut rec = crate::record::ResolverRecord::new(resolver);
		rec.benchmark = Some(crate::record::BenchmarkResult {
			categories: BTreeMap::new(),
			overall_score,
			success_rate,
			rank: 0,
			tie_group: None,
		});
		rec
	}

	#[test]
	fn test_ranking_order() {
		let mut records = vec![
			make_test_record("slow", 100.0, 95.0),
			make_test_record("fast", 10.0, 99.0),
			make_test_record("medium", 50.0, 97.0),
		];
		rank_records(&mut records, &SortMode::Score);
		assert_eq!(records[0].benchmark.as_ref().unwrap().rank, 1);
		assert_eq!(records[0].resolver.label, "fast");
		assert_eq!(records[1].resolver.label, "medium");
		assert_eq!(records[2].resolver.label, "slow");
	}

	#[test]
	fn test_compute_uncertainty_basic() {
		let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0];
		let uncertainty = compute_uncertainty(&values);
		assert!((uncertainty - 2.9652).abs() < 0.01);
	}

	#[test]
	fn test_compute_uncertainty_single() {
		let values = vec![42.0];
		assert_eq!(compute_uncertainty(&values), 0.0);
	}

	#[test]
	fn test_compute_uncertainty_empty() {
		let values: Vec<f64> = vec![];
		assert_eq!(compute_uncertainty(&values), 0.0);
	}

	#[test]
	fn test_detect_ties_close_scores() {
		let mut records = vec![
			make_test_record("a", 10.0, 99.0),
			make_test_record("b", 11.0, 98.0),
			make_test_record("c", 50.0, 95.0),
		];
		rank_records(&mut records, &SortMode::Score);
		let uncertainties = vec![5.0, 5.0, 0.1];
		detect_ties_on_records(&mut records, &uncertainties);

		// a and b should be tied (diff=1, threshold=10)
		assert_eq!(records[0].benchmark.as_ref().unwrap().tie_group, Some("1-2".to_string()));
		assert_eq!(records[1].benchmark.as_ref().unwrap().tie_group, Some("1-2".to_string()));
		assert_eq!(records[2].benchmark.as_ref().unwrap().tie_group, None);
	}

	#[test]
	fn test_detect_ties_no_ties() {
		let mut records = vec![
			make_test_record("a", 10.0, 99.0),
			make_test_record("b", 100.0, 95.0),
		];
		rank_records(&mut records, &SortMode::Score);
		let uncertainties = vec![0.1, 0.1];
		detect_ties_on_records(&mut records, &uncertainties);

		assert_eq!(records[0].benchmark.as_ref().unwrap().tie_group, None);
		assert_eq!(records[1].benchmark.as_ref().unwrap().tie_group, None);
	}

	#[test]
	fn test_sort_by_category() {
		let mut rec_a = make_test_record("a", 10.0, 99.0);
		rec_a.benchmark.as_mut().unwrap().categories.insert(
			"cached".to_string(), SetStats { p50_ms: 50.0, ..Default::default() },
		);
		let mut rec_b = make_test_record("b", 20.0, 99.0);
		rec_b.benchmark.as_mut().unwrap().categories.insert(
			"cached".to_string(), SetStats { p50_ms: 10.0, ..Default::default() },
		);

		let mut records = vec![rec_a, rec_b];
		rank_records(&mut records, &SortMode::Category("cached".to_string()));
		// b has lower cached p50, should rank first
		assert_eq!(records[0].resolver.label, "b");
		assert_eq!(records[1].resolver.label, "a");
	}
}
