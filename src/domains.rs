use anyhow::{anyhow, Result};

/// Return a list of popular domains likely to be cached by DNS resolvers.
pub fn default_warm_domains() -> Vec<String> {
	vec![
		"google.com",
		"youtube.com",
		"facebook.com",
		"amazon.com",
		"wikipedia.org",
		"twitter.com",
		"reddit.com",
		"netflix.com",
		"microsoft.com",
		"apple.com",
	].into_iter().map(String::from).collect()
}

/// Return a list of uncommon domains unlikely to be cached by resolvers.
pub fn default_cold_domains() -> Vec<String> {
	vec![
		"zzz-test-domain-001.example.com",
		"obscure-site-42.info",
		"rare-domain-test.org",
		"uncommon-benchmark-dns.net",
		"test-cold-cache-alpha.com",
		"test-cold-cache-beta.com",
		"test-cold-cache-gamma.com",
		"test-cold-cache-delta.com",
		"test-cold-cache-epsilon.com",
		"bench-dns-cold-001.net",
		"bench-dns-cold-002.net",
		"bench-dns-cold-003.net",
		"bench-dns-cold-004.org",
		"bench-dns-cold-005.org",
		"bench-dns-cold-006.info",
		"bench-dns-cold-007.info",
		"bench-dns-cold-008.com",
		"bench-dns-cold-009.com",
		"bench-dns-cold-010.net",
		"bench-dns-cold-011.net",
		"dns-latency-test-aaa.org",
		"dns-latency-test-bbb.org",
		"dns-latency-test-ccc.com",
		"dns-latency-test-ddd.com",
		"dns-latency-test-eee.net",
		"dns-latency-test-fff.net",
		"dns-latency-test-ggg.info",
		"dns-latency-test-hhh.info",
		"dns-latency-test-iii.org",
		"dns-latency-test-jjj.org",
		"cold-query-benchmark-01.com",
		"cold-query-benchmark-02.com",
		"cold-query-benchmark-03.net",
		"cold-query-benchmark-04.net",
		"cold-query-benchmark-05.org",
		"cold-query-benchmark-06.org",
		"cold-query-benchmark-07.info",
		"cold-query-benchmark-08.info",
		"cold-query-benchmark-09.com",
		"cold-query-benchmark-10.com",
		"resolver-perf-test-alpha.net",
		"resolver-perf-test-bravo.net",
		"resolver-perf-test-charlie.org",
		"resolver-perf-test-delta.org",
		"resolver-perf-test-echo.com",
		"resolver-perf-test-foxtrot.com",
		"resolver-perf-test-golf.info",
		"resolver-perf-test-hotel.info",
		"resolver-perf-test-india.net",
		"resolver-perf-test-juliet.net",
	].into_iter().map(String::from).collect()
}

/// Read domains from a file, one per line.
///
/// Blank lines and lines starting with '#' are skipped.
pub fn read_domain_file(path: &str) -> Result<Vec<String>> {
	let content = std::fs::read_to_string(path)
		.map_err(|e| anyhow!("failed to read domain file '{}': {}", path, e))?;
	let domains: Vec<String> = content.lines()
		.map(|line| line.trim().to_string())
		.filter(|line| !line.is_empty() && !line.starts_with('#'))
		.collect();
	Ok(domains)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_warm_domains_size() {
		let warm = default_warm_domains();
		assert!(!warm.is_empty());
		assert_eq!(warm.len(), 10);
	}

	#[test]
	fn test_cold_domains_size() {
		let cold = default_cold_domains();
		assert!(!cold.is_empty());
		assert_eq!(cold.len(), 50);
	}
}
