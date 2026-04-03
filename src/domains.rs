use std::collections::BTreeMap;
use anyhow::{anyhow, Result};

/// Default query domains CSV, embedded at compile time.
const DEFAULT_QUERY_DOMAINS_CSV: &str = include_str!("../query_domains.csv");

/// Parse a query domains CSV string into a map of category -> domain list.
///
/// CSV format: domain,category (with header row).
/// Categories are sorted alphabetically via BTreeMap for deterministic output.
fn parse_query_domains_csv(csv_text: &str) -> BTreeMap<String, Vec<String>> {
	let mut categories: BTreeMap<String, Vec<String>> = BTreeMap::new();
	for line in csv_text.lines().skip(1) {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		// Split on first comma only
		let parts: Vec<&str> = line.splitn(2, ',').collect();
		if parts.len() != 2 {
			continue;
		}
		let domain = parts[0].trim().to_string();
		let category = parts[1].trim().to_string();
		if !domain.is_empty() && !category.is_empty() {
			categories.entry(category).or_default().push(domain);
		}
	}
	categories
}

/// Load the built-in default query domains from the embedded CSV.
pub fn load_default_query_domains() -> BTreeMap<String, Vec<String>> {
	parse_query_domains_csv(DEFAULT_QUERY_DOMAINS_CSV)
}

/// Return a list of domains guaranteed not to exist.
///
/// Used for NXDOMAIN interception detection. These use the .invalid TLD
/// (reserved by RFC 2606) and domains that definitively do not exist.
/// Available via --nxdomain-domains CLI flag for custom test domains.
pub fn default_nxdomain_domains() -> Vec<String> {
	vec![
		"nxdomain-test-0001.invalid",
		"nxdomain-test-0002.invalid",
		"nxdomain-test-0003.invalid",
		"thisdomaindoesnotexist-benchmark-check.invalid",
		"dns-benchmark-nxdomain-probe.invalid",
		"nxdomain-canary-test.invalid",
		"resolver-honesty-check.invalid",
		"definitely-not-a-real-domain.invalid",
		"benchmark-interception-test.invalid",
		"nxdomain-validation-probe.invalid",
	].into_iter().map(String::from).collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_default_query_domains_loads() {
		let categories = load_default_query_domains();
		// Should have at least cached, uncached, tld, dotcom
		assert!(categories.contains_key("cached"), "missing 'cached' category");
		assert!(categories.contains_key("uncached"), "missing 'uncached' category");
		assert!(categories.contains_key("tld"), "missing 'tld' category");
		assert!(categories.contains_key("dotcom"), "missing 'dotcom' category");
	}

	#[test]
	fn test_cached_domains_size() {
		let categories = load_default_query_domains();
		let cached = &categories["cached"];
		assert_eq!(cached.len(), 10);
	}

	#[test]
	fn test_uncached_domains_size() {
		let categories = load_default_query_domains();
		let uncached = &categories["uncached"];
		assert_eq!(uncached.len(), 50);
	}

	#[test]
	fn test_tld_domains_diverse() {
		let categories = load_default_query_domains();
		let tld = &categories["tld"];
		assert!(tld.len() >= 30, "expected at least 30 TLD domains, got {}", tld.len());
		// Check diverse TLDs
		let mut tlds: Vec<String> = tld.iter()
			.filter_map(|d| d.rsplit('.').next().map(String::from))
			.collect();
		tlds.sort();
		tlds.dedup();
		assert!(tlds.len() >= 15, "expected at least 15 unique TLDs, got {}", tlds.len());
	}

	#[test]
	fn test_nxdomain_domains_size() {
		let nx = default_nxdomain_domains();
		assert!(!nx.is_empty());
		assert_eq!(nx.len(), 10);
	}

	#[test]
	fn test_nxdomain_domains_are_invalid_tld() {
		let nx = default_nxdomain_domains();
		for domain in &nx {
			assert!(domain.ends_with(".invalid"), "expected .invalid TLD: {}", domain);
		}
	}

	#[test]
	fn test_parse_csv_handles_comments_and_blanks() {
		let csv = "domain,category\n\ngoogle.com,cached\n# comment\nexample.com,test\n";
		let result = parse_query_domains_csv(csv);
		assert_eq!(result["cached"], vec!["google.com"]);
		assert_eq!(result["test"], vec!["example.com"]);
	}

	#[test]
	fn test_dnssec_category_present() {
		let categories = load_default_query_domains();
		assert!(categories.contains_key("dnssec"), "missing 'dnssec' category");
		assert!(categories["dnssec"].len() >= 10, "expected at least 10 DNSSEC domains");
	}
}
