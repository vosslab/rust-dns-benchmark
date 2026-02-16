use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand::rngs::StdRng;
use anyhow::Result;

use hickory_proto::op::ResponseCode;

use crate::transport::{
	ResolverConfig, QueryType, QueryResult, BenchmarkConfig, CharacterizationResult,
};
use crate::dns::{build_query, parse_response, check_nxdomain_interception};
use crate::stats::{
	compute_set_stats, compute_uncertainty, detect_ties,
	rank_resolvers, ResolverStats, ScoredResolver,
};

/// Send a single DNS query over UDP and measure latency.
///
/// Creates a dedicated socket per query to avoid response stealing between
/// concurrent tasks sharing the same resolver socket.
async fn send_udp_query(
	resolver: std::net::SocketAddr,
	query_bytes: &[u8],
	timeout: Duration,
	txid: u16,
	domain: &str,
	query_type: QueryType,
) -> QueryResult {
	let resolver_label = resolver.ip().to_string();

	// Bind a dedicated socket for this query
	let bind_addr = if resolver.is_ipv4() {
		"0.0.0.0:0"
	} else {
		"[::]:0"
	};
	let socket = match UdpSocket::bind(bind_addr).await {
		Ok(s) => s,
		Err(_) => {
			return QueryResult {
				resolver: resolver_label,
				domain: domain.to_string(),
				query_type,
				rcode: None,
				latency: timeout,
				success: false,
				timeout: true,
			};
		}
	};

	// Send the query and start timing immediately around send+recv
	let start = Instant::now();
	if socket.send_to(query_bytes, resolver).await.is_err() {
		return QueryResult {
			resolver: resolver_label,
			domain: domain.to_string(),
			query_type,
			rcode: None,
			latency: timeout,
			success: false,
			timeout: true,
		};
	}

	// Receive with timeout, retry recv on txid mismatch
	// Use 4096-byte buffer to handle EDNS-extended responses
	let mut buf = vec![0u8; 4096];
	let max_retries = 3;
	for _ in 0..max_retries {
		let elapsed = start.elapsed();
		if elapsed >= timeout {
			break;
		}
		let remaining = timeout - elapsed;

		match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
			Ok(Ok((len, _src))) => {
				let latency = start.elapsed();
				match parse_response(&buf[..len], txid, domain, query_type) {
					Ok(response) => {
						let success =
							response.rcode == ResponseCode::NoError;
						return QueryResult {
							resolver: resolver_label,
							domain: domain.to_string(),
							query_type,
							rcode: Some(response.rcode_str),
							latency,
							success,
							timeout: false,
						};
					}
					Err(_) => {
						// txid mismatch or parse error, retry recv
						continue;
					}
				}
			}
			_ => {
				// Timeout or recv error
				break;
			}
		}
	}

	// Exhausted retries or timed out
	QueryResult {
		resolver: resolver_label,
		domain: domain.to_string(),
		query_type,
		rcode: None,
		latency: start.elapsed(),
		success: false,
		timeout: true,
	}
}

/// A single query task: resolver + domain + query type + set membership
#[derive(Clone, Debug)]
struct QueryTask {
	resolver: ResolverConfig,
	domain: String,
	query_type: QueryType,
	set_name: String,
}

/// Run NXDOMAIN interception characterization for all resolvers.
///
/// Sends a single probe query per resolver for a known-bad domain.
/// If the resolver returns NoError with A records, it is marked as intercepting.
pub async fn run_characterization(
	resolvers: &mut [ResolverConfig],
	timeout: Duration,
) -> Vec<CharacterizationResult> {
	println!("Checking NXDOMAIN interception ({} resolvers)...", resolvers.len());

	// Run all probes concurrently for speed
	let semaphore = std::sync::Arc::new(Semaphore::new(32));
	let mut handles = Vec::new();

	for i in 0..resolvers.len() {
		let addr = resolvers[i].addr;
		let label = resolvers[i].label.clone();
		let sem = semaphore.clone();
		let timeout = timeout;

		handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let intercepts = check_nxdomain_interception(addr, timeout).await;
			(i, label, addr, intercepts)
		}));
	}

	let mut results = Vec::new();
	for handle in handles {
		match handle.await {
			Ok((idx, label, addr, intercepts)) => {
				resolvers[idx].intercepts_nxdomain = intercepts;
				let status = if intercepts { "INTERCEPTS NXDOMAIN" } else { "OK" };
				println!("  {} ({}): {}", label, addr.ip(), status);
				results.push(CharacterizationResult {
					label,
					addr,
					intercepts_nxdomain: intercepts,
					reachable: true,
				});
			}
			Err(e) => {
				eprintln!("Warning: characterization task failed: {}", e);
			}
		}
	}

	println!();
	results
}

/// Run discovery prefilter to narrow a large resolver list to the best N.
///
/// Phase 1: fast parallel screen with 1 query per resolver (500ms timeout).
/// Phase 2: parallel warm-only benchmark on survivors, keep top N by p50.
pub async fn run_discovery(
	resolvers: &[ResolverConfig],
	warm_domains: &[String],
	config: &BenchmarkConfig,
) -> Result<Vec<ResolverConfig>> {
	let top_n = config.top_n;
	println!("Discovery mode: screening {} resolvers...", resolvers.len());

	// Phase 1: fast parallel reachability screen (1 query, 500ms timeout)
	let screen_timeout = Duration::from_millis(500);
	let screen_domain = warm_domains.first()
		.map(|s| s.as_str())
		.unwrap_or("google.com");
	let semaphore = std::sync::Arc::new(Semaphore::new(config.max_inflight));

	let mut screen_handles = Vec::new();
	for resolver in resolvers {
		let sem = semaphore.clone();
		let addr = resolver.addr;
		let dnssec = config.dnssec;
		let domain = screen_domain.to_string();
		let resolver_clone = resolver.clone();

		screen_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let txid: u16 = rand::random();
			let query_bytes = match build_query(
				&domain, QueryType::A, txid, dnssec,
			) {
				Ok(b) => b,
				Err(_) => return (resolver_clone, false),
			};
			let result = send_udp_query(
				addr, &query_bytes, screen_timeout,
				txid, &domain, QueryType::A,
			).await;
			(resolver_clone, result.success)
		}));
	}

	let mut survivors = Vec::new();
	for handle in screen_handles {
		if let Ok((resolver, reachable)) = handle.await {
			if reachable {
				survivors.push(resolver);
			}
		}
	}

	let unreachable = resolvers.len() - survivors.len();
	println!(
		"  Screen: {}/{} resolvers reachable ({} unreachable, dropped)",
		survivors.len(), resolvers.len(), unreachable,
	);

	if survivors.len() <= top_n {
		println!("  Keeping all {} survivors (at or below --top {})", survivors.len(), top_n);
		return Ok(survivors);
	}

	// Phase 2: parallel warm-only benchmark on survivors
	println!("  Quick benchmark on {} survivors...", survivors.len());
	let timeout_penalty_ms = config.timeout.as_millis() as f64;
	let mut resolver_latencies: HashMap<String, Vec<f64>> = HashMap::new();

	// Build all tasks and run concurrently
	let mut bench_handles = Vec::new();
	for resolver in &survivors {
		for domain in warm_domains {
			let sem = semaphore.clone();
			let addr = resolver.addr;
			let timeout = config.timeout;
			let dnssec = config.dnssec;
			let domain_clone = domain.clone();

			bench_handles.push(tokio::spawn(async move {
				let _permit = sem.acquire().await.unwrap();
				let txid: u16 = rand::random();
				let query_bytes = match build_query(
					&domain_clone, QueryType::A, txid, dnssec,
				) {
					Ok(b) => b,
					Err(_) => return (addr.ip().to_string(), None),
				};
				let result = send_udp_query(
					addr, &query_bytes, timeout,
					txid, &domain_clone, QueryType::A,
				).await;
				if result.success {
					let latency_ms = result.latency.as_secs_f64() * 1000.0;
					(addr.ip().to_string(), Some(latency_ms))
				} else {
					(addr.ip().to_string(), None)
				}
			}));
		}
	}

	for handle in bench_handles {
		if let Ok((ip, latency_opt)) = handle.await {
			if let Some(latency_ms) = latency_opt {
				resolver_latencies
					.entry(ip)
					.or_default()
					.push(latency_ms);
			}
		}
	}

	// Sort by warm p50 and keep top N
	let mut scored: Vec<(String, f64)> = resolver_latencies.iter()
		.map(|(ip, lats)| {
			let stats = compute_set_stats(lats, lats.len(), 0, lats.len(), timeout_penalty_ms);
			(ip.clone(), stats.p50_ms)
		})
		.collect();
	scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

	let top_ips: Vec<String> = scored.into_iter()
		.take(top_n)
		.map(|(ip, _)| ip)
		.collect();

	let filtered: Vec<ResolverConfig> = survivors.into_iter()
		.filter(|r| top_ips.contains(&r.addr.ip().to_string()))
		.collect();

	println!("  Kept top {} resolvers for full benchmark", filtered.len());
	Ok(filtered)
}

/// Run the full benchmark across all resolvers and domains.
///
/// Executes multiple rounds of queries, shuffling the order each round.
/// Returns scored and ranked resolver results.
pub async fn run_benchmark(
	resolvers: &[ResolverConfig],
	warm_domains: &[String],
	cold_domains: &[String],
	tld_domains: &[String],
	config: &BenchmarkConfig,
) -> Result<Vec<ScoredResolver>> {
	// Determine which query types to use
	let query_types = if config.query_aaaa {
		vec![QueryType::A, QueryType::AAAA]
	} else {
		vec![QueryType::A]
	};

	// Build the list of all query tasks
	let mut tasks: Vec<QueryTask> = Vec::new();
	for resolver in resolvers {
		for domain in warm_domains {
			for &qt in &query_types {
				tasks.push(QueryTask {
					resolver: resolver.clone(),
					domain: domain.clone(),
					query_type: qt,
					set_name: "warm".to_string(),
				});
			}
		}
		for domain in cold_domains {
			for &qt in &query_types {
				tasks.push(QueryTask {
					resolver: resolver.clone(),
					domain: domain.clone(),
					query_type: qt,
					set_name: "cold".to_string(),
				});
			}
		}
		// TLD domains (only if enabled)
		if config.query_tld {
			for domain in tld_domains {
				for &qt in &query_types {
					tasks.push(QueryTask {
						resolver: resolver.clone(),
						domain: domain.clone(),
						query_type: qt,
						set_name: "tld".to_string(),
					});
				}
			}
		}
	}

	let total_queries = tasks.len() * config.rounds as usize;
	println!("  {} queries across {} resolvers, {} rounds",
		total_queries, resolvers.len(), config.rounds);

	// Collect all results across rounds
	let mut all_results: Vec<(QueryTask, QueryResult)> = Vec::new();
	let semaphore = std::sync::Arc::new(Semaphore::new(config.max_inflight));

	// Create a seeded RNG for reproducible shuffling
	let mut rng = match config.seed {
		Some(seed) => StdRng::seed_from_u64(seed),
		None => StdRng::from_entropy(),
	};

	for round in 0..config.rounds {
		println!("  Round {}/{}", round + 1, config.rounds);

		// Shuffle tasks for this round
		let mut round_tasks = tasks.clone();
		round_tasks.shuffle(&mut rng);

		// Spawn all query tasks for this round
		let mut handles = Vec::new();
		for task in round_tasks {
			let sem = semaphore.clone();
			let timeout = config.timeout;
			let spacing = config.inter_query_spacing;
			let dnssec = config.dnssec;

			handles.push(tokio::spawn(async move {
				// Acquire semaphore permit for concurrency control
				let _permit = sem.acquire().await.unwrap();

				// Inter-query spacing delay
				if !spacing.is_zero() {
					tokio::time::sleep(spacing).await;
				}

				// Generate a random transaction ID
				let txid: u16 = rand::random();

				// Build the DNS query
				let query_bytes = match build_query(
					&task.domain, task.query_type, txid, dnssec,
				) {
					Ok(bytes) => bytes,
					Err(_) => {
						return (task.clone(), QueryResult {
							resolver: task.resolver.addr.ip().to_string(),
							domain: task.domain.clone(),
							query_type: task.query_type,
							rcode: None,
							latency: Duration::ZERO,
							success: false,
							timeout: false,
						});
					}
				};

				// Send query and measure latency (each task gets its own socket)
				let result = send_udp_query(
					task.resolver.addr, &query_bytes,
					timeout, txid, &task.domain, task.query_type,
				).await;

				(task, result)
			}));
		}

		// Collect results from all tasks in this round
		for handle in handles {
			match handle.await {
				Ok((task, result)) => {
					all_results.push((task, result));
				}
				Err(e) => {
					eprintln!("Warning: task failed: {}", e);
				}
			}
		}
	}

	// Aggregate results per resolver
	let timeout_penalty_ms = config.timeout.as_millis() as f64;
	let mut resolver_data: HashMap<String, ResolverAggregation> = HashMap::new();

	for (task, result) in &all_results {
		let entry = resolver_data
			.entry(result.resolver.clone())
			.or_default();
		let latency_ms = result.latency.as_secs_f64() * 1000.0;

		match task.set_name.as_str() {
			"warm" => {
				if result.success {
					entry.warm_latencies.push(latency_ms);
				}
				entry.warm_total += 1;
				if result.success { entry.warm_success += 1; }
				if result.timeout { entry.warm_timeout += 1; }
			}
			"cold" => {
				if result.success {
					entry.cold_latencies.push(latency_ms);
				}
				entry.cold_total += 1;
				if result.success { entry.cold_success += 1; }
				if result.timeout { entry.cold_timeout += 1; }
			}
			"tld" => {
				if result.success {
					entry.tld_latencies.push(latency_ms);
				}
				entry.tld_total += 1;
				if result.success { entry.tld_success += 1; }
				if result.timeout { entry.tld_timeout += 1; }
			}
			_ => {}
		}
	}

	// Map resolver IP back to display label and interception status
	let label_map: HashMap<String, String> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.label.clone()))
		.collect();
	let intercept_map: HashMap<String, bool> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.intercepts_nxdomain))
		.collect();

	// Build ResolverStats for each resolver
	let mut stats_list: Vec<ResolverStats> = Vec::new();
	// Track all latencies per resolver for uncertainty computation
	let mut all_latencies_per_resolver: Vec<Vec<f64>> = Vec::new();

	for (resolver_ip, agg) in &resolver_data {
		let warm_stats = compute_set_stats(
			&agg.warm_latencies, agg.warm_success,
			agg.warm_timeout, agg.warm_total, timeout_penalty_ms,
		);
		let cold_stats = compute_set_stats(
			&agg.cold_latencies, agg.cold_success,
			agg.cold_timeout, agg.cold_total, timeout_penalty_ms,
		);

		// TLD stats (optional)
		let tld_stats = if config.query_tld && agg.tld_total > 0 {
			Some(compute_set_stats(
				&agg.tld_latencies, agg.tld_success,
				agg.tld_timeout, agg.tld_total, timeout_penalty_ms,
			))
		} else {
			None
		};

		// Overall score is the average of warm and cold set scores
		let overall_score = (warm_stats.score + cold_stats.score) / 2.0;
		let total = agg.warm_total + agg.cold_total + agg.tld_total;
		let total_success = agg.warm_success + agg.cold_success + agg.tld_success;
		let success_rate = if total > 0 {
			(total_success as f64 / total as f64) * 100.0
		} else {
			0.0
		};

		let label = label_map.get(resolver_ip)
			.cloned()
			.unwrap_or_else(|| resolver_ip.clone());
		let intercepts = intercept_map.get(resolver_ip)
			.copied()
			.unwrap_or(false);

		// Combine all latencies for uncertainty computation
		let mut combined = agg.warm_latencies.clone();
		combined.extend(&agg.cold_latencies);
		all_latencies_per_resolver.push(combined);

		stats_list.push(ResolverStats {
			label,
			addr: resolver_ip.clone(),
			warm: warm_stats,
			cold: cold_stats,
			tld: tld_stats,
			overall_score,
			success_rate,
			intercepts_nxdomain: intercepts,
		});
	}

	let mut ranked = rank_resolvers(stats_list);

	// Compute uncertainties and detect ties
	let mut uncertainties: Vec<f64> = Vec::new();
	for scored in &ranked {
		// Find the matching latency data by label
		let mut found = false;
		for (i, (ip, _)) in resolver_data.iter().enumerate() {
			let label = label_map.get(ip).cloned().unwrap_or_else(|| ip.clone());
			if label == scored.stats.label {
				uncertainties.push(compute_uncertainty(&all_latencies_per_resolver[i]));
				found = true;
				break;
			}
		}
		if !found {
			uncertainties.push(0.0);
		}
	}
	detect_ties(&mut ranked, &uncertainties);

	Ok(ranked)
}

/// Intermediate aggregation of query results for a single resolver
#[derive(Default)]
struct ResolverAggregation {
	warm_latencies: Vec<f64>,
	cold_latencies: Vec<f64>,
	tld_latencies: Vec<f64>,
	warm_success: usize,
	cold_success: usize,
	tld_success: usize,
	warm_total: usize,
	cold_total: usize,
	tld_total: usize,
	warm_timeout: usize,
	cold_timeout: usize,
	tld_timeout: usize,
}
