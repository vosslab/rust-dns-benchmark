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

/// Return a list of real domains unlikely to be cached by resolvers.
///
/// These are real, resolvable domains across diverse TLDs. They should
/// trigger actual uncached resolution rather than NXDOMAIN negative caching.
pub fn default_cold_domains() -> Vec<String> {
	vec![
		// Government and institutional (.gov, .edu)
		"archives.gov",
		"usgs.gov",
		"noaa.gov",
		"energy.gov",
		"census.gov",
		"si.edu",
		"caltech.edu",
		"mit.edu",
		"stanford.edu",
		"cornell.edu",
		// International research and institutions
		"cern.ch",
		"csiro.au",
		"keio.ac.jp",
		"ethz.ch",
		"mpg.de",
		"cnrs.fr",
		"nrc.ca",
		"anu.edu.au",
		"cam.ac.uk",
		"tudelft.nl",
		// Country-code TLD variety
		"ibge.gov.br",
		"kb.se",
		"onb.ac.at",
		"nationaalarchief.nl",
		"riksarkivet.no",
		"arkisto.fi",
		"nla.gov.au",
		"ndl.go.jp",
		"snu.ac.kr",
		"natlib.govt.nz",
		// Less common TLDs (.io, .dev, .app, .info, .museum)
		"pkg.dev",
		"fonts.google.com",
		"crates.io",
		"httpbin.org",
		"lobste.rs",
		"arxiv.org",
		"jstor.org",
		"archive.org",
		"gutenberg.org",
		"openlibrary.org",
		// Regional sites
		"rtve.es",
		"yle.fi",
		"dr.dk",
		"nrk.no",
		"svt.se",
		"rtp.pt",
		"rte.ie",
		"srf.ch",
		"orf.at",
		"vrt.be",
	].into_iter().map(String::from).collect()
}

/// Return a list of domains guaranteed not to exist.
///
/// Used for NXDOMAIN interception detection. These use the .invalid TLD
/// (reserved by RFC 2606) and domains that definitively do not exist.
/// Available via --nxdomain-domains CLI flag for custom test domains.
#[allow(dead_code)]
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

/// Return a list of domains spanning many different TLDs.
///
/// One real domain per TLD for measuring uncached resolution across
/// diverse TLD infrastructure.
pub fn default_tld_domains() -> Vec<String> {
	vec![
		// Generic TLDs
		"icann.org",        // .org
		"iana.org",         // .org (different authority path)
		"ietf.org",         // .org (standards body)
		"example.net",      // .net
		"verisign.com",     // .com
		// Tech TLDs
		"pkg.dev",          // .dev
		"web.app",          // .app
		"dart.dev",         // .dev
		// Government / education
		"nist.gov",         // .gov
		"loc.gov",          // .gov
		"mit.edu",          // .edu
		// European ccTLDs
		"ox.ac.uk",         // .uk
		"tu-berlin.de",     // .de
		"inria.fr",         // .fr
		"uva.nl",           // .nl
		"kth.se",           // .se
		"lu.ch",            // .ch
		"tuwien.at",        // .at
		"kuleuven.be",      // .be
		"tcd.ie",           // .ie
		"ulisboa.pt",       // .pt
		"uio.no",           // .no
		"oulu.fi",          // .fi
		"ku.dk",            // .dk
		// Asia-Pacific ccTLDs
		"keio.ac.jp",       // .jp
		"snu.ac.kr",        // .kr
		"iitb.ac.in",       // .in
		"uq.edu.au",        // .au
		"auckland.ac.nz",   // .nz
		// Americas / Africa ccTLDs
		"ubc.ca",           // .ca
		"unam.mx",          // .mx
		"usp.br",           // .br
		"uct.ac.za",        // .za
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

	#[test]
	fn test_cold_domains_are_real() {
		// Verify none of the cold domains use fake/test prefixes
		let cold = default_cold_domains();
		for domain in &cold {
			assert!(!domain.starts_with("bench-dns-cold-"), "fake domain found: {}", domain);
			assert!(!domain.starts_with("test-cold-cache-"), "fake domain found: {}", domain);
			assert!(!domain.starts_with("resolver-perf-test-"), "fake domain found: {}", domain);
			assert!(!domain.starts_with("zzz-test-domain-"), "fake domain found: {}", domain);
		}
	}

	#[test]
	fn test_nxdomain_domains_size() {
		let nx = default_nxdomain_domains();
		assert!(!nx.is_empty());
		assert_eq!(nx.len(), 10);
	}

	#[test]
	fn test_nxdomain_domains_are_invalid_tld() {
		// All NXDOMAIN test domains should use .invalid TLD
		let nx = default_nxdomain_domains();
		for domain in &nx {
			assert!(domain.ends_with(".invalid"), "expected .invalid TLD: {}", domain);
		}
	}

	#[test]
	fn test_tld_domains_size() {
		let tld = default_tld_domains();
		assert!(!tld.is_empty());
		assert!(tld.len() >= 30, "expected at least 30 TLD domains, got {}", tld.len());
	}

	#[test]
	fn test_tld_domains_diverse_tlds() {
		// Check that we have diverse TLDs (not all the same)
		let tld = default_tld_domains();
		let mut tlds: Vec<String> = tld.iter()
			.filter_map(|d| d.rsplit('.').next().map(String::from))
			.collect();
		tlds.sort();
		tlds.dedup();
		assert!(tlds.len() >= 15, "expected at least 15 unique TLDs, got {}", tlds.len());
	}
}
