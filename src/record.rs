use std::collections::BTreeMap;

use crate::stats::SetStats;
use crate::transport::Resolver;

/// Result of the discovery screening stage for a single resolver.
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
	pub passed: bool,
	/// Latency in milliseconds; None if stage failed before measurement
	pub latency_ms: Option<f64>,
	/// Reason for pass/fail (e.g. "reachable", "timeout", "connect_failed")
	pub reason: String,
}

/// Result of the characterization stage for a single resolver.
#[derive(Debug, Clone)]
pub struct CharacterizationResult {
	pub reachable: bool,
	pub attempts_used: u32,
	pub successes: u32,
	/// Median latency in milliseconds; None if unreachable
	pub latency_ms: Option<f64>,
	/// Whether the resolver intercepts NXDOMAIN responses
	pub intercepts_nxdomain: bool,
	/// Whether the resolver protects against DNS rebinding attacks
	pub rebinding_protection: Option<bool>,
	/// Whether the resolver validates DNSSEC signatures
	pub validates_dnssec: Option<bool>,
}

/// Result of the qualification scoring stage for a single resolver.
#[derive(Debug, Clone)]
pub struct QualificationResult {
	pub score: f64,
	pub promoted: bool,
	pub p50_ms: f64,
	pub stddev_ms: f64,
	pub timeout_rate: f64,
}

/// Result of the full benchmark stage for a single resolver.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
	/// Per-category statistics (e.g. "cached", "tld", "dotcom")
	pub categories: BTreeMap<String, SetStats>,
	pub overall_score: f64,
	pub success_rate: f64,
	// NOTE: rank and tie_group are comparison outputs, not intrinsic measurements.
	// Pragmatic compromise; a later cleanup could split ranking metadata out.
	pub rank: usize,
	pub tie_group: Option<String>,
}

/// Per-run accumulator for a single resolver.
/// Each pipeline stage writes its result onto the record.
#[derive(Debug, Clone)]
pub struct ResolverRecord {
	pub resolver: Resolver,
	pub discovery: Option<DiscoveryResult>,
	pub characterization: Option<CharacterizationResult>,
	pub qualification: Option<QualificationResult>,
	pub benchmark: Option<BenchmarkResult>,
}

//============================================
impl ResolverRecord {
	/// Create a new record for a resolver with no stage results.
	pub fn new(resolver: Resolver) -> Self {
		ResolverRecord {
			resolver,
			discovery: None,
			characterization: None,
			qualification: None,
			benchmark: None,
		}
	}

	/// Whether this resolver intercepts NXDOMAIN (from characterization).
	pub fn intercepts_nxdomain(&self) -> bool {
		self.characterization.as_ref()
			.map(|c| c.intercepts_nxdomain)
			.unwrap_or(false)
	}

	/// Whether this resolver has DNS rebinding protection (from characterization).
	pub fn rebinding_protection(&self) -> Option<bool> {
		self.characterization.as_ref()
			.and_then(|c| c.rebinding_protection)
	}

	/// Whether this resolver validates DNSSEC (from characterization).
	pub fn validates_dnssec(&self) -> Option<bool> {
		self.characterization.as_ref()
			.and_then(|c| c.validates_dnssec)
	}
}
