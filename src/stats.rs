/// Statistics for a set of queries (warm or cold)
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

/// Full resolver statistics with warm and cold sets
#[derive(Debug, Clone)]
pub struct ResolverStats {
	pub label: String,
	pub warm: SetStats,
	pub cold: SetStats,
	pub overall_score: f64,
	pub success_rate: f64,
}

/// Scored and ranked resolver
#[derive(Debug, Clone)]
pub struct ScoredResolver {
	pub rank: usize,
	pub stats: ResolverStats,
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
pub fn set_score(stats: &SetStats, timeout_penalty_ms: f64) -> f64 {
	let timeout_rate = if stats.total_count > 0 {
		stats.timeout_count as f64 / stats.total_count as f64
	} else {
		0.0
	};
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

/// Rank resolvers by overall score (average of warm and cold scores), ascending.
///
/// Lower scores are better (lower latency).
pub fn rank_resolvers(mut resolvers: Vec<ResolverStats>) -> Vec<ScoredResolver> {
	// Sort by overall score ascending (lower is better)
	resolvers.sort_by(|a, b| {
		a.overall_score.partial_cmp(&b.overall_score)
			.unwrap_or(std::cmp::Ordering::Equal)
	});
	resolvers.into_iter()
		.enumerate()
		.map(|(i, stats)| ScoredResolver {
			rank: i + 1,
			stats,
		})
		.collect()
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

	#[test]
	fn test_ranking_order() {
		let resolvers = vec![
			ResolverStats {
				label: "slow".to_string(),
				warm: SetStats::default(),
				cold: SetStats::default(),
				overall_score: 100.0,
				success_rate: 95.0,
			},
			ResolverStats {
				label: "fast".to_string(),
				warm: SetStats::default(),
				cold: SetStats::default(),
				overall_score: 10.0,
				success_rate: 99.0,
			},
			ResolverStats {
				label: "medium".to_string(),
				warm: SetStats::default(),
				cold: SetStats::default(),
				overall_score: 50.0,
				success_rate: 97.0,
			},
		];
		let ranked = rank_resolvers(resolvers);
		assert_eq!(ranked[0].rank, 1);
		assert_eq!(ranked[0].stats.label, "fast");
		assert_eq!(ranked[1].rank, 2);
		assert_eq!(ranked[1].stats.label, "medium");
		assert_eq!(ranked[2].rank, 3);
		assert_eq!(ranked[2].stats.label, "slow");
	}
}
