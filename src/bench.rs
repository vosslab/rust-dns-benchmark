use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand::rngs::StdRng;
use anyhow::Result;

use hickory_proto::op::ResponseCode;
use rustls::ClientConfig;
use tokio_rustls::TlsConnector;

use crate::transport::{
	DnsTransport, ResolverConfig, QueryType, QueryResult, BenchmarkConfig,
};
use crate::dns::{
	build_query, parse_response, check_nxdomain_interception,
	check_rebinding_protection, check_dnssec_validation,
};
use crate::stats::{
	compute_set_stats, compute_uncertainty, detect_ties,
	rank_resolvers, ResolverStats, ScoredResolver,
};

/// Shared pool of reqwest clients for DoH, keyed by resolver URL
type DohClientPool = HashMap<String, reqwest::Client>;

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

/// Send a single DNS query over TLS (DoT, RFC 7858) and measure latency.
///
/// Creates a new TCP+TLS connection per query (no reuse) to measure
/// cold-start latency including TLS handshake. Uses 2-byte length prefix
/// per DNS-over-TCP convention.
async fn send_dot_query(
	resolver: std::net::SocketAddr,
	hostname: &str,
	query_bytes: &[u8],
	timeout: Duration,
	_txid: u16,
	domain: &str,
	query_type: QueryType,
) -> QueryResult {
	let resolver_label = resolver.ip().to_string();
	let make_timeout_result = || QueryResult {
		resolver: resolver_label.clone(),
		domain: domain.to_string(),
		query_type,
		rcode: None,
		latency: timeout,
		success: false,
		timeout: true,
	};

	// Build TLS config with system root certificates
	let root_store = rustls::RootCertStore::from_iter(
		webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
	);
	let tls_config = ClientConfig::builder()
		.with_root_certificates(root_store)
		.with_no_client_auth();
	let connector = TlsConnector::from(Arc::new(tls_config));

	// Parse SNI hostname
	let server_name = match rustls::pki_types::ServerName::try_from(hostname.to_string()) {
		Ok(sn) => sn,
		Err(_) => {
			// Fall back to IP-based if hostname doesn't parse
			match rustls::pki_types::ServerName::try_from(resolver.ip().to_string()) {
				Ok(sn) => sn,
				Err(_) => return make_timeout_result(),
			}
		}
	};

	let start = Instant::now();

	// TCP connect with timeout
	let tcp_stream = match tokio::time::timeout(timeout, TcpStream::connect(resolver)).await {
		Ok(Ok(s)) => s,
		_ => return make_timeout_result(),
	};

	// TLS handshake with remaining timeout
	let remaining = timeout.saturating_sub(start.elapsed());
	let mut tls_stream = match tokio::time::timeout(
		remaining, connector.connect(server_name, tcp_stream),
	).await {
		Ok(Ok(s)) => s,
		_ => return make_timeout_result(),
	};

	// Send DNS query with 2-byte TCP length prefix
	let len_prefix = (query_bytes.len() as u16).to_be_bytes();
	let remaining = timeout.saturating_sub(start.elapsed());
	let send_result = tokio::time::timeout(remaining, async {
		tls_stream.write_all(&len_prefix).await?;
		tls_stream.write_all(query_bytes).await?;
		tls_stream.flush().await
	}).await;
	if send_result.is_err() || send_result.unwrap().is_err() {
		return make_timeout_result();
	}

	// Read 2-byte response length prefix
	let remaining = timeout.saturating_sub(start.elapsed());
	let resp_len = match tokio::time::timeout(remaining, async {
		let mut len_buf = [0u8; 2];
		tls_stream.read_exact(&mut len_buf).await?;
		Ok::<u16, std::io::Error>(u16::from_be_bytes(len_buf))
	}).await {
		Ok(Ok(len)) => len as usize,
		_ => return make_timeout_result(),
	};

	// Read response body
	let remaining = timeout.saturating_sub(start.elapsed());
	let resp_bytes = match tokio::time::timeout(remaining, async {
		let mut buf = vec![0u8; resp_len];
		tls_stream.read_exact(&mut buf).await?;
		Ok::<Vec<u8>, std::io::Error>(buf)
	}).await {
		Ok(Ok(buf)) => buf,
		_ => return make_timeout_result(),
	};

	let latency = start.elapsed();

	// Parse the DNS response
	match parse_response(&resp_bytes, _txid, domain, query_type) {
		Ok(response) => {
			let success = response.rcode == ResponseCode::NoError;
			QueryResult {
				resolver: resolver_label,
				domain: domain.to_string(),
				query_type,
				rcode: Some(response.rcode_str),
				latency,
				success,
				timeout: false,
			}
		}
		Err(_) => make_timeout_result(),
	}
}

/// Send a single DNS query over HTTPS (DoH, RFC 8484) and measure latency.
///
/// Uses a shared reqwest::Client per resolver for HTTP/2 connection reuse,
/// which reflects how DoH works in practice.
async fn send_doh_query(
	url: &str,
	query_bytes: &[u8],
	timeout: Duration,
	domain: &str,
	query_type: QueryType,
	client: &reqwest::Client,
) -> QueryResult {
	let make_timeout_result = || QueryResult {
		resolver: url.to_string(),
		domain: domain.to_string(),
		query_type,
		rcode: None,
		latency: timeout,
		success: false,
		timeout: true,
	};

	let start = Instant::now();

	// POST DNS query as application/dns-message (RFC 8484)
	let response = match tokio::time::timeout(timeout, async {
		client.post(url)
			.header("Content-Type", "application/dns-message")
			.header("Accept", "application/dns-message")
			.body(query_bytes.to_vec())
			.send()
			.await
	}).await {
		Ok(Ok(r)) => r,
		_ => return make_timeout_result(),
	};

	// Read response body
	let remaining = timeout.saturating_sub(start.elapsed());
	let resp_bytes = match tokio::time::timeout(remaining, response.bytes()).await {
		Ok(Ok(b)) => b,
		_ => return make_timeout_result(),
	};

	let latency = start.elapsed();

	// Parse the DNS wire-format response
	// DoH responses don't need txid validation since HTTP handles request matching
	match parse_response(&resp_bytes, 0, domain, query_type) {
		Ok(response) => {
			// Accept even if txid doesn't match (DoH handles correlation via HTTP)
			let success = response.rcode == ResponseCode::NoError;
			QueryResult {
				resolver: url.to_string(),
				domain: domain.to_string(),
				query_type,
				rcode: Some(response.rcode_str),
				latency,
				success,
				timeout: false,
			}
		}
		Err(_) => {
			// Try parsing without txid check by using txid from response
			if resp_bytes.len() >= 2 {
				let resp_txid = u16::from_be_bytes([resp_bytes[0], resp_bytes[1]]);
				if let Ok(response) = parse_response(&resp_bytes, resp_txid, domain, query_type) {
					let success = response.rcode == ResponseCode::NoError;
					return QueryResult {
						resolver: url.to_string(),
						domain: domain.to_string(),
						query_type,
						rcode: Some(response.rcode_str),
						latency,
						success,
						timeout: false,
					};
				}
			}
			make_timeout_result()
		}
	}
}

/// Dispatch a query to the appropriate transport based on resolver config.
async fn dispatch_query(
	resolver: &ResolverConfig,
	query_bytes: &[u8],
	timeout: Duration,
	txid: u16,
	domain: &str,
	query_type: QueryType,
	doh_clients: &DohClientPool,
) -> QueryResult {
	match &resolver.transport {
		DnsTransport::Udp => {
			send_udp_query(resolver.addr, query_bytes, timeout, txid, domain, query_type).await
		}
		DnsTransport::Dot { hostname } => {
			send_dot_query(
				resolver.addr, hostname, query_bytes, timeout,
				txid, domain, query_type,
			).await
		}
		DnsTransport::Doh { url } => {
			let client = doh_clients.get(url).expect("DoH client not found");
			send_doh_query(url, query_bytes, timeout, domain, query_type, client).await
		}
	}
}

/// Build a DoH client pool with one reqwest::Client per DoH resolver URL.
pub fn build_doh_client_pool(resolvers: &[ResolverConfig]) -> DohClientPool {
	let mut pool = HashMap::new();
	for r in resolvers {
		if let DnsTransport::Doh { url } = &r.transport {
			pool.entry(url.clone()).or_insert_with(|| {
				reqwest::Client::builder()
					.use_rustls_tls()
					.http2_prior_knowledge()
					.build()
					.expect("failed to build DoH HTTP client")
			});
		}
	}
	pool
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
	resolvers: &mut Vec<ResolverConfig>,
	config: &BenchmarkConfig,
	nxdomain_domains: &[String],
) {
	let timeout = config.timeout;

	// Phase 0: v2-style reachability pre-check
	// Give each resolver up to DEFAULT_CHAR_ATTEMPTS chances to reply within DEFAULT_CHAR_TIMEOUT_MS
	let char_timeout = Duration::from_millis(crate::transport::DEFAULT_CHAR_TIMEOUT_MS);
	let char_attempts = crate::transport::DEFAULT_CHAR_ATTEMPTS;
	println!("Reachability pre-check ({} resolvers, {} attempts, {} ms timeout)...",
		resolvers.len(), char_attempts, char_timeout.as_millis());

	let semaphore = std::sync::Arc::new(Semaphore::new(32));
	let mut reachability_handles = Vec::new();

	for (i, resolver) in resolvers.iter().enumerate() {
		let addr = resolver.addr;
		let label = resolver.label.clone();
		let sem = semaphore.clone();
		let ct = char_timeout;
		let attempts = char_attempts;

		reachability_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			// Send up to `attempts` A queries for google.com, check if any reply in time
			let mut any_fast = false;
			for _ in 0..attempts {
				let txid: u16 = rand::random();
				let query_bytes = match crate::dns::build_query(
					"google.com", crate::transport::QueryType::A, txid, false,
				) {
					Ok(b) => b,
					Err(_) => continue,
				};
				let result = send_udp_query(addr, &query_bytes, ct, txid, "google.com", crate::transport::QueryType::A).await;
				if result.success {
					any_fast = true;
					break;
				}
			}
			(i, label, addr, any_fast)
		}));
	}

	// Collect reachability results and sideline unreachable resolvers
	let mut reachable = vec![false; resolvers.len()];
	for handle in reachability_handles {
		match handle.await {
			Ok((idx, label, addr, is_reachable)) => {
				reachable[idx] = is_reachable;
				let status = if is_reachable { "reachable" } else { "SIDELINED (unreachable)" };
				println!("  {} ({}): {}", label, addr.ip(), status);
			}
			Err(e) => {
				eprintln!("Warning: reachability check failed: {}", e);
			}
		}
	}

	// Remove unreachable resolvers
	let before = resolvers.len();
	let mut idx = 0;
	resolvers.retain(|_| {
		let keep = reachable[idx];
		idx += 1;
		keep
	});
	let sidelined = before - resolvers.len();
	println!("  {} reachable, {} sidelined, {} total", resolvers.len(), sidelined, before);
	println!();

	// Phase 1: NXDOMAIN interception check
	println!("Checking NXDOMAIN interception ({} resolvers)...", resolvers.len());

	let mut handles = Vec::new();

	for (i, resolver) in resolvers.iter().enumerate() {
		let addr = resolver.addr;
		let label = resolver.label.clone();
		let sem = semaphore.clone();
		let tm = timeout;
		let domains = nxdomain_domains.to_vec();

		handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let intercepts = check_nxdomain_interception(addr, tm, &domains).await;
			(i, label, addr, intercepts)
		}));
	}

	for handle in handles {
		match handle.await {
			Ok((idx, label, addr, intercepts)) => {
				resolvers[idx].intercepts_nxdomain = intercepts;
				let status = if intercepts { "INTERCEPTS NXDOMAIN" } else { "OK" };
				println!("  {} ({}): {}", label, addr.ip(), status);
			}
			Err(e) => {
				eprintln!("Warning: characterization task failed: {}", e);
			}
		}
	}
	println!();

	// Check rebinding protection
	println!("Checking DNS rebinding protection ({} resolvers)...", resolvers.len());
	let mut rebind_handles = Vec::new();
	for (i, resolver) in resolvers.iter().enumerate() {
		let addr = resolver.addr;
		let label = resolver.label.clone();
		let sem = semaphore.clone();
		let tm = timeout;

		rebind_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let protection = check_rebinding_protection(addr, tm).await;
			(i, label, addr, protection)
		}));
	}

	for handle in rebind_handles {
		match handle.await {
			Ok((idx, label, addr, protection)) => {
				resolvers[idx].rebinding_protection = protection;
				let status = match protection {
					Some(true) => "PROTECTED",
					Some(false) => "not protected",
					None => "unknown",
				};
				println!("  {} ({}): {}", label, addr.ip(), status);
			}
			Err(e) => {
				eprintln!("Warning: rebinding check failed: {}", e);
			}
		}
	}
	println!();

	// Check DNSSEC validation
	println!("Checking DNSSEC validation ({} resolvers)...", resolvers.len());
	let mut dnssec_handles = Vec::new();
	for (i, resolver) in resolvers.iter().enumerate() {
		let addr = resolver.addr;
		let label = resolver.label.clone();
		let sem = semaphore.clone();
		let tm = timeout;

		dnssec_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let validates = check_dnssec_validation(addr, tm).await;
			(i, label, addr, validates)
		}));
	}

	for handle in dnssec_handles {
		match handle.await {
			Ok((idx, label, addr, validates)) => {
				resolvers[idx].validates_dnssec = validates;
				let status = match validates {
					Some(true) => "VALIDATES",
					Some(false) => "does not validate",
					None => "unknown",
				};
				println!("  {} ({}): {}", label, addr.ip(), status);
			}
			Err(e) => {
				eprintln!("Warning: DNSSEC validation check failed: {}", e);
			}
		}
	}

	println!();
}

/// Run discovery prefilter to narrow a large resolver list to the best N.
///
/// Phase 1: fast parallel screen with 1 query per resolver (500ms timeout).
/// Phase 2: parallel warm-only benchmark on survivors, keep top N by p50.
pub async fn run_discovery(
	resolvers: &[ResolverConfig],
	categories: &std::collections::BTreeMap<String, Vec<String>>,
	config: &BenchmarkConfig,
	doh_clients: &DohClientPool,
) -> Result<Vec<ResolverConfig>> {
	let top_n = config.top_n;
	println!("Discovery mode: screening {} resolvers...", resolvers.len());

	// Pick discovery domains from the first category with enough entries
	let discovery_domains: &[String] = categories.values()
		.find(|domains| domains.len() >= 5)
		.or_else(|| categories.values().next())
		.map(|v| v.as_slice())
		.unwrap_or(&[]);

	// Phase 1: fast parallel reachability screen (1 query, 500ms timeout)
	let screen_timeout = Duration::from_millis(500);
	let screen_domain = discovery_domains.first()
		.map(|s| s.as_str())
		.unwrap_or("google.com");
	let semaphore = std::sync::Arc::new(Semaphore::new(config.max_inflight));

	let mut screen_handles = Vec::new();
	for resolver in resolvers {
		let sem = semaphore.clone();
		let dnssec = config.dnssec;
		let domain = screen_domain.to_string();
		let resolver_clone = resolver.clone();
		let doh_clients = doh_clients.clone();

		screen_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let txid: u16 = rand::random();
			let query_bytes = match build_query(
				&domain, QueryType::A, txid, dnssec,
			) {
				Ok(b) => b,
				Err(_) => return (resolver_clone, false),
			};
			let result = dispatch_query(
				&resolver_clone, &query_bytes, screen_timeout,
				txid, &domain, QueryType::A, &doh_clients,
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

	if config.exhaustive {
		println!("  Exhaustive mode: keeping all {} reachable resolvers (no top-N cut)", survivors.len());
		config.telemetry.log_pipeline("discovery_reachable", survivors.len());
		config.telemetry.log_pipeline("discovery_top_n", survivors.len());
		return Ok(survivors);
	}

	if survivors.len() <= top_n {
		println!("  Keeping all {} survivors (at or below --top {})", survivors.len(), top_n);
		config.telemetry.log_pipeline("discovery_reachable", survivors.len());
		config.telemetry.log_pipeline("discovery_top_n", survivors.len());
		return Ok(survivors);
	}

	// Phase 2: parallel warm-only benchmark on survivors
	println!("  Quick benchmark on {} survivors...", survivors.len());
	let timeout_penalty_ms = config.timeout.as_millis() as f64;
	let mut resolver_latencies: HashMap<String, Vec<f64>> = HashMap::new();

	// Build all tasks and run concurrently
	let mut bench_handles = Vec::new();
	for resolver in &survivors {
		for domain in discovery_domains {
			let sem = semaphore.clone();
			let resolver_clone = resolver.clone();
			let timeout = config.timeout;
			let dnssec = config.dnssec;
			let domain_clone = domain.clone();
			let doh_clients = doh_clients.clone();

			bench_handles.push(tokio::spawn(async move {
				let _permit = sem.acquire().await.unwrap();
				let txid: u16 = rand::random();
				let query_bytes = match build_query(
					&domain_clone, QueryType::A, txid, dnssec,
				) {
					Ok(b) => b,
					Err(_) => return (resolver_clone.addr.ip().to_string(), None),
				};
				let result = dispatch_query(
					&resolver_clone, &query_bytes, timeout,
					txid, &domain_clone, QueryType::A, &doh_clients,
				).await;
				if result.success {
					let latency_ms = result.latency.as_secs_f64() * 1000.0;
					(resolver_clone.addr.ip().to_string(), Some(latency_ms))
				} else {
					(resolver_clone.addr.ip().to_string(), None)
				}
			}));
		}
	}

	for handle in bench_handles {
		if let Ok((ip, Some(latency_ms))) = handle.await {
			resolver_latencies
				.entry(ip)
				.or_default()
				.push(latency_ms);
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
	config.telemetry.log_pipeline("discovery_reachable", resolver_latencies.len());
	config.telemetry.log_pipeline("discovery_top_n", filtered.len());
	Ok(filtered)
}

/// Run the full benchmark across all resolvers and domains.
///
/// Executes multiple rounds of queries, shuffling the order each round.
/// Returns scored and ranked resolver results.
#[allow(clippy::too_many_arguments)]
pub async fn run_benchmark(
	resolvers: &[ResolverConfig],
	categories: &std::collections::BTreeMap<String, Vec<String>>,
	config: &BenchmarkConfig,
	doh_clients: &DohClientPool,
) -> Result<Vec<ScoredResolver>> {
	// Determine which query types to use
	let query_types = if config.query_aaaa {
		vec![QueryType::A, QueryType::AAAA]
	} else {
		vec![QueryType::A]
	};

	// Build the list of all query tasks from all categories
	let mut tasks: Vec<QueryTask> = Vec::new();
	for resolver in resolvers {
		for (category_name, domains) in categories {
			for domain in domains {
				for &qt in &query_types {
					tasks.push(QueryTask {
						resolver: resolver.clone(),
						domain: domain.clone(),
						query_type: qt,
						set_name: category_name.clone(),
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

	// Track sidelined resolvers (by IP string)
	let mut sidelined: std::collections::HashSet<String> = std::collections::HashSet::new();
	// Build label map for sidelining messages
	let label_map_for_sideline: HashMap<String, String> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.label.clone()))
		.collect();

	for round in 0..config.rounds {
		// Filter out sidelined resolvers for this round
		let mut round_tasks = tasks.clone();
		if !sidelined.is_empty() {
			round_tasks.retain(|t| !sidelined.contains(&t.resolver.addr.ip().to_string()));
		}
		round_tasks.shuffle(&mut rng);

		let round_total = round_tasks.len();
		let completed_count = Arc::new(AtomicUsize::new(0));

		// Progress monitor: print status every 500ms
		let progress_counter = completed_count.clone();
		let round_num = round + 1;
		let total_rounds = config.rounds;
		let monitor = tokio::spawn(async move {
			loop {
				tokio::time::sleep(Duration::from_millis(500)).await;
				let done = progress_counter.load(Ordering::Relaxed);
				let pct = if round_total > 0 { done * 100 / round_total } else { 100 };
				eprint!("\r  Round {}/{}: {}/{} queries ({}%)",
					round_num, total_rounds, done, round_total, pct);
			}
		});

		// Spawn all query tasks for this round
		let mut handles = Vec::new();
		for task in round_tasks {
			let sem = semaphore.clone();
			let timeout = config.timeout;
			let spacing = config.inter_query_spacing;
			let dnssec = config.dnssec;
			let doh_clients = doh_clients.clone();
			let progress = completed_count.clone();

			handles.push(tokio::spawn(async move {
				// Acquire semaphore permit for concurrency control
				let _permit = sem.acquire().await.unwrap();

				// Inter-query spacing delay with random jitter (0-50% of spacing)
				if !spacing.is_zero() {
					let jitter_ms = rand::random::<u64>() % (spacing.as_millis() as u64 / 2 + 1);
					tokio::time::sleep(spacing + std::time::Duration::from_millis(jitter_ms)).await;
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

				// Send query via appropriate transport
				let result = dispatch_query(
					&task.resolver, &query_bytes,
					timeout, txid, &task.domain, task.query_type,
					&doh_clients,
				).await;

				// Increment progress counter
				progress.fetch_add(1, Ordering::Relaxed);

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

		// Stop progress monitor and print final line for this round
		monitor.abort();
		eprint!("\r  Round {}/{}: {}/{} queries (100%)    \n",
			round + 1, config.rounds, round_total, round_total);

		// Log round completion to telemetry
		let round_failures = all_results.iter()
			.filter(|(t, r)| {
				let ip = t.resolver.addr.ip().to_string();
				!sidelined.contains(&ip) && !r.success
			})
			.count();
		config.telemetry.log_round_complete(round + 1, round_total, round_failures);

		// Mid-benchmark sidelining: check for slow/dead resolvers after each round
		if round < config.rounds - 1 {
			let mut per_resolver: HashMap<String, (usize, usize, Vec<f64>)> = HashMap::new();
			for (task, result) in &all_results {
				let ip = task.resolver.addr.ip().to_string();
				if sidelined.contains(&ip) {
					continue;
				}
				let entry = per_resolver.entry(ip).or_insert((0, 0, Vec::new()));
				entry.0 += 1; // total
				if result.timeout { entry.1 += 1; } // timeouts
				if result.success {
					entry.2.push(result.latency.as_secs_f64() * 1000.0);
				}
			}
			for (ip, (total, timeouts, latencies)) in &per_resolver {
				let timeout_rate = *timeouts as f64 / *total as f64;
				// Sideline if >80% timeouts
				if timeout_rate > 0.8 {
					let label = label_map_for_sideline.get(ip)
						.cloned().unwrap_or_else(|| ip.clone());
					let reason = format!("{:.0}% timeouts", timeout_rate * 100.0);
					println!("  Sidelined {} ({}) -- {}", label, ip, reason);
					config.telemetry.log_sidelined(ip, &reason, round + 1);
					sidelined.insert(ip.clone());
					continue;
				}
				// Sideline if p50 exceeds threshold
				if !latencies.is_empty() {
					let mut sorted = latencies.clone();
					sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
					let p50 = sorted[sorted.len() / 2];
					if p50 > crate::transport::DEFAULT_SIDELINE_MS {
						let label = label_map_for_sideline.get(ip)
							.cloned().unwrap_or_else(|| ip.clone());
						let reason = format!("p50 {:.0} ms > {} ms threshold", p50, crate::transport::DEFAULT_SIDELINE_MS as u64);
						println!("  Sidelined {} ({}) -- {}", label, ip, reason);
						config.telemetry.log_sidelined(ip, &reason, round + 1);
						sidelined.insert(ip.clone());
					}
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

		// Aggregate into the appropriate category bucket
		let cat = entry.categories
			.entry(task.set_name.clone())
			.or_default();
		if result.success {
			cat.latencies.push(latency_ms);
			cat.success += 1;
		}
		cat.total += 1;
		if result.timeout {
			cat.timeout += 1;
		}
	}

	// Map resolver IP back to display label and interception status
	let label_map: HashMap<String, String> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.label.clone()))
		.collect();
	let intercept_map: HashMap<String, bool> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.intercepts_nxdomain))
		.collect();
	let system_map: HashMap<String, bool> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.is_system))
		.collect();
	let transport_map: HashMap<String, String> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.transport.to_string()))
		.collect();
	let ptr_map: HashMap<String, Option<String>> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.ptr_name.clone()))
		.collect();
	let rebinding_map: HashMap<String, Option<bool>> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.rebinding_protection))
		.collect();
	let dnssec_map: HashMap<String, Option<bool>> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.validates_dnssec))
		.collect();

	// Build ResolverStats for each resolver
	let mut stats_list: Vec<ResolverStats> = Vec::new();
	// Track all latencies per resolver for uncertainty computation
	let mut all_latencies_per_resolver: Vec<Vec<f64>> = Vec::new();

	for (resolver_ip, agg) in &resolver_data {
		// Compute per-category stats
		let mut cat_stats: std::collections::BTreeMap<String, crate::stats::SetStats> = std::collections::BTreeMap::new();
		for (cat_name, cat_agg) in &agg.categories {
			let stats = compute_set_stats(
				&cat_agg.latencies, cat_agg.success,
				cat_agg.timeout, cat_agg.total, timeout_penalty_ms,
			);
			cat_stats.insert(cat_name.clone(), stats);
		}

		// Overall score: average of all categories that have data
		let scored_categories: Vec<f64> = cat_stats.values()
			.filter(|s| s.total_count > 0)
			.map(|s| s.score)
			.collect();
		let overall_score = if scored_categories.is_empty() {
			f64::INFINITY
		} else {
			scored_categories.iter().sum::<f64>() / scored_categories.len() as f64
		};

		// Total success rate across all categories
		let total: usize = agg.categories.values().map(|c| c.total).sum();
		let total_success: usize = agg.categories.values().map(|c| c.success).sum();
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
		let mut combined: Vec<f64> = Vec::new();
		for cat_agg in agg.categories.values() {
			combined.extend(&cat_agg.latencies);
		}
		all_latencies_per_resolver.push(combined);

		let is_system = system_map.get(resolver_ip)
			.copied()
			.unwrap_or(false);

		let transport_label = transport_map.get(resolver_ip)
			.cloned()
			.unwrap_or_else(|| "UDP".to_string());

		let ptr_name = ptr_map.get(resolver_ip)
			.cloned()
			.unwrap_or(None);
		let rebinding = rebinding_map.get(resolver_ip)
			.copied()
			.unwrap_or(None);
		let dnssec_validates = dnssec_map.get(resolver_ip)
			.copied()
			.unwrap_or(None);

		stats_list.push(ResolverStats {
			label,
			addr: resolver_ip.clone(),
			transport: transport_label,
			categories: cat_stats,
			overall_score,
			success_rate,
			intercepts_nxdomain: intercepts,
			is_system,
			ptr_name,
			rebinding_protection: rebinding,
			validates_dnssec: dnssec_validates,
		});
	}

	let mut ranked = rank_resolvers(stats_list, &config.sort_mode);

	// Build label-to-uncertainty map for O(1) lookup
	let uncertainty_map: HashMap<String, f64> = resolver_data.iter()
		.enumerate()
		.map(|(i, (ip, _))| {
			let label = label_map.get(ip).cloned().unwrap_or_else(|| ip.clone());
			(label, compute_uncertainty(&all_latencies_per_resolver[i]))
		})
		.collect();

	// Look up uncertainties in ranked order for tie detection
	let uncertainties: Vec<f64> = ranked.iter()
		.map(|scored| {
			uncertainty_map.get(&scored.stats.label).copied().unwrap_or(0.0)
		})
		.collect();
	detect_ties(&mut ranked, &uncertainties);

	Ok(ranked)
}

/// Per-category aggregation of query results
#[derive(Default)]
struct CategoryAgg {
	latencies: Vec<f64>,
	success: usize,
	total: usize,
	timeout: usize,
}

/// Intermediate aggregation of query results for a single resolver
#[derive(Default)]
struct ResolverAggregation {
	categories: std::collections::BTreeMap<String, CategoryAgg>,
}
