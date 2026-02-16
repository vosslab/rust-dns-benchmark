/// Statistics for a set of queries (warm, cold, or tld)
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

/// Full resolver statistics with warm, cold, and TLD sets
#[derive(Debug, Clone)]
pub struct ResolverStats {
	pub label: String,
	pub addr: String,
	pub warm: SetStats,
	pub cold: SetStats,
	pub tld: Option<SetStats>,
	pub overall_score: f64,
	pub success_rate: f64,
	pub intercepts_nxdomain: bool,
}

/// Scored and ranked resolver
#[derive(Debug, Clone)]
pub struct ScoredResolver {
	pub rank: usize,
	pub stats: ResolverStats,
	/// Tie group label (e.g. "1-3") when resolvers are statistically tied
	pub tie_group: Option<String>,
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

/// Detect ties among ranked resolvers based on overlapping uncertainty bands.
///
/// For consecutive pairs: if |score_a - score_b| < uncertainty_a + uncertainty_b,
/// they are tied. Groups tied resolvers and assigns shared rank labels.
pub fn detect_ties(resolvers: &mut [ScoredResolver], uncertainties: &[f64]) {
	if resolvers.len() < 2 || uncertainties.len() != resolvers.len() {
		return;
	}

	// Build tie groups using a union-find approach on consecutive pairs
	let n = resolvers.len();
	let mut group_id = vec![0usize; n];
	for i in 0..n {
		group_id[i] = i;
	}

	// Check consecutive pairs for overlap
	for i in 0..(n - 1) {
		let score_a = resolvers[i].stats.overall_score;
		let score_b = resolvers[i + 1].stats.overall_score;
		let diff = (score_a - score_b).abs();
		let threshold = uncertainties[i] + uncertainties[i + 1];

		if diff < threshold {
			// Merge into same group (use the earlier group ID)
			let target = group_id[i];
			let source = group_id[i + 1];
			// Propagate group membership
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
		// Find all members of this group
		let members: Vec<usize> = (0..n).filter(|&j| group_id[j] == gid).collect();

		if members.len() > 1 {
			let first_rank = members[0] + 1;
			let last_rank = members[members.len() - 1] + 1;
			let label = format!("{}-{}", first_rank, last_rank);
			for &m in &members {
				resolvers[m].tie_group = Some(label.clone());
			}
		}

		i = members.last().map(|&l| l + 1).unwrap_or(i + 1);
	}
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
			tie_group: None,
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
				addr: "0.0.0.0".to_string(),
				warm: SetStats::default(),
				cold: SetStats::default(),
				tld: None,
				overall_score: 100.0,
				success_rate: 95.0,
				intercepts_nxdomain: false,
			},
			ResolverStats {
				label: "fast".to_string(),
				addr: "0.0.0.0".to_string(),
				warm: SetStats::default(),
				cold: SetStats::default(),
				tld: None,
				overall_score: 10.0,
				success_rate: 99.0,
				intercepts_nxdomain: false,
			},
			ResolverStats {
				label: "medium".to_string(),
				addr: "0.0.0.0".to_string(),
				warm: SetStats::default(),
				cold: SetStats::default(),
				tld: None,
				overall_score: 50.0,
				success_rate: 97.0,
				intercepts_nxdomain: false,
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

	#[test]
	fn test_compute_uncertainty_basic() {
		// Symmetric data: deviations from median=5 are [4,3,2,1,0,1,2,3,4]
		let values = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0];
		let uncertainty = compute_uncertainty(&values);
		// MAD of abs deviations [0,1,1,2,2,3,3,4,4] = median = 2
		// uncertainty = 1.4826 * 2 = 2.9652
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
		let mut resolvers = vec![
			ScoredResolver {
				rank: 1,
				stats: ResolverStats {
					label: "a".to_string(),
					addr: "0.0.0.0".to_string(),
					warm: SetStats::default(),
					cold: SetStats::default(),
					tld: None,
					overall_score: 10.0,
					success_rate: 99.0,
					intercepts_nxdomain: false,
				},
				tie_group: None,
			},
			ScoredResolver {
				rank: 2,
				stats: ResolverStats {
					label: "b".to_string(),
					addr: "0.0.0.0".to_string(),
					warm: SetStats::default(),
					cold: SetStats::default(),
					tld: None,
					overall_score: 11.0,
					success_rate: 98.0,
					intercepts_nxdomain: false,
				},
				tie_group: None,
			},
			ScoredResolver {
				rank: 3,
				stats: ResolverStats {
					label: "c".to_string(),
					addr: "0.0.0.0".to_string(),
					warm: SetStats::default(),
					cold: SetStats::default(),
					tld: None,
					overall_score: 50.0,
					success_rate: 95.0,
					intercepts_nxdomain: false,
				},
				tie_group: None,
			},
		];
		// Large uncertainties for a and b, small for c
		let uncertainties = vec![5.0, 5.0, 0.1];
		detect_ties(&mut resolvers, &uncertainties);

		// a and b should be tied (diff=1, threshold=10)
		assert_eq!(resolvers[0].tie_group, Some("1-2".to_string()));
		assert_eq!(resolvers[1].tie_group, Some("1-2".to_string()));
		// c should not be tied
		assert_eq!(resolvers[2].tie_group, None);
	}

	#[test]
	fn test_detect_ties_no_ties() {
		let mut resolvers = vec![
			ScoredResolver {
				rank: 1,
				stats: ResolverStats {
					label: "a".to_string(),
					addr: "0.0.0.0".to_string(),
					warm: SetStats::default(),
					cold: SetStats::default(),
					tld: None,
					overall_score: 10.0,
					success_rate: 99.0,
					intercepts_nxdomain: false,
				},
				tie_group: None,
			},
			ScoredResolver {
				rank: 2,
				stats: ResolverStats {
					label: "b".to_string(),
					addr: "0.0.0.0".to_string(),
					warm: SetStats::default(),
					cold: SetStats::default(),
					tld: None,
					overall_score: 100.0,
					success_rate: 95.0,
					intercepts_nxdomain: false,
				},
				tie_group: None,
			},
		];
		// Very small uncertainties
		let uncertainties = vec![0.1, 0.1];
		detect_ties(&mut resolvers, &uncertainties);

		assert_eq!(resolvers[0].tie_group, None);
		assert_eq!(resolvers[1].tie_group, None);
	}
}
