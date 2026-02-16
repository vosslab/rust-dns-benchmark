use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand::rngs::StdRng;
use anyhow::Result;

use hickory_proto::op::ResponseCode;

use crate::transport::{ResolverConfig, QueryType, QueryResult, BenchmarkConfig};
use crate::dns::{build_query, parse_response};
use crate::stats::{compute_set_stats, rank_resolvers, ResolverStats, ScoredResolver};

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
	let mut buf = vec![0u8; 512];
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

/// Run the full benchmark across all resolvers and domains.
///
/// Executes multiple rounds of queries, shuffling the order each round.
/// Returns scored and ranked resolver results.
pub async fn run_benchmark(
	resolvers: &[ResolverConfig],
	warm_domains: &[String],
	cold_domains: &[String],
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
	}

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
					&task.domain, task.query_type, txid
				) {
					Ok(bytes) => bytes,
					Err(_) => {
						return (task.clone(), QueryResult {
							resolver: task.resolver.label.clone(),
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

		if task.set_name == "warm" {
			if result.success {
				entry.warm_latencies.push(latency_ms);
			}
			entry.warm_total += 1;
			if result.success { entry.warm_success += 1; }
			if result.timeout { entry.warm_timeout += 1; }
		} else {
			if result.success {
				entry.cold_latencies.push(latency_ms);
			}
			entry.cold_total += 1;
			if result.success { entry.cold_success += 1; }
			if result.timeout { entry.cold_timeout += 1; }
		}
	}

	// Map resolver IP back to display label
	let label_map: HashMap<String, String> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.label.clone()))
		.collect();

	// Build ResolverStats for each resolver
	let mut stats_list: Vec<ResolverStats> = Vec::new();
	for (resolver_ip, agg) in &resolver_data {
		let warm_stats = compute_set_stats(
			&agg.warm_latencies, agg.warm_success,
			agg.warm_timeout, agg.warm_total, timeout_penalty_ms,
		);
		let cold_stats = compute_set_stats(
			&agg.cold_latencies, agg.cold_success,
			agg.cold_timeout, agg.cold_total, timeout_penalty_ms,
		);

		// Overall score is the average of warm and cold set scores
		let overall_score = (warm_stats.score + cold_stats.score) / 2.0;
		let total = agg.warm_total + agg.cold_total;
		let total_success = agg.warm_success + agg.cold_success;
		let success_rate = if total > 0 {
			(total_success as f64 / total as f64) * 100.0
		} else {
			0.0
		};

		let label = label_map.get(resolver_ip)
			.cloned()
			.unwrap_or_else(|| resolver_ip.clone());

		stats_list.push(ResolverStats {
			label,
			warm: warm_stats,
			cold: cold_stats,
			overall_score,
			success_rate,
		});
	}

	let ranked = rank_resolvers(stats_list);
	Ok(ranked)
}

/// Intermediate aggregation of query results for a single resolver
#[derive(Default)]
struct ResolverAggregation {
	warm_latencies: Vec<f64>,
	cold_latencies: Vec<f64>,
	warm_success: usize,
	cold_success: usize,
	warm_total: usize,
	cold_total: usize,
	warm_timeout: usize,
	cold_timeout: usize,
}
