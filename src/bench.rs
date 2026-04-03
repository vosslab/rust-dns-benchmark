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
	resolver_class,
};

/// Timeout for Phase 1 discovery reachability screen -- UDP (ms)
pub const SCREEN_TIMEOUT_MS: u64 = 500;
/// Timeout for Phase 1 discovery reachability screen -- DoT/DoH (ms)
/// Longer to account for TCP connect + TLS handshake overhead
pub const SCREEN_TLS_TIMEOUT_MS: u64 = 2000;
/// Concurrency for discovery screening
/// 128 is the sweet spot: halves screening time vs 64 without triggering
/// macOS UDP socket rate limiting (256 causes instant ICMP rejections)
pub const DISCOVERY_CONCURRENCY: usize = 128;
use crate::dns::{
	build_query, parse_response, check_nxdomain_interception,
	check_rebinding_protection, check_dnssec_validation,
};
use crate::stats::{
	compute_set_stats, compute_uncertainty, detect_ties,
	rank_resolvers, ResolverStats, ScoredResolver,
};

use tokio::task::JoinHandle;

/// Shared pool of reqwest clients for DoH, keyed by resolver URL
type DohClientPool = HashMap<String, reqwest::Client>;

/// Format a duration in seconds to a human-readable string like "2m 15s" or "8s".
fn format_duration_secs(secs: u64) -> String {
	if secs >= 60 {
		format!("{}m {}s", secs / 60, secs % 60)
	} else {
		format!("{}s", secs)
	}
}

/// Round an ETA (in seconds) up to reduce display jitter.
/// Under 60s: round up to nearest 5s.
/// 1-10m: round up to nearest 15s.
/// Over 10m: round up to nearest 30s.
fn round_eta_up(secs: f64) -> u64 {
	let s = secs.ceil() as u64;
	if s == 0 {
		return 0;
	}
	let bucket = if s < 60 {
		5
	} else if s < 600 {
		15
	} else {
		30
	};
	// Round up to next multiple of bucket
	((s + bucket - 1) / bucket) * bucket
}

/// Spawn a progress monitor that prints live progress with EMA-smoothed ETA.
///
/// Returns the JoinHandle so the caller can abort it when done.
/// The monitor prints to stderr every 500ms with carriage-return overwrite.
pub fn spawn_progress_monitor(
	label: String,
	completed: Arc<AtomicUsize>,
	total: usize,
	start: Instant,
) -> JoinHandle<()> {
	tokio::spawn(async move {
		// EMA-smoothed rate for jitter reduction
		let mut smoothed_rate: Option<f64> = None;
		let alpha = 0.1;
		loop {
			tokio::time::sleep(Duration::from_millis(500)).await;
			let done = completed.load(Ordering::Relaxed);
			let pct = if total > 0 { done * 100 / total } else { 100 };
			let elapsed = start.elapsed().as_secs_f64();
			// Calculate ETA with EMA smoothing
			let eta_str = if done == 0 || elapsed < 0.001 {
				"--".to_string()
			} else {
				let current_rate = done as f64 / elapsed;
				let rate = match smoothed_rate {
					Some(prev) => {
						let r = alpha * current_rate + (1.0 - alpha) * prev;
						smoothed_rate = Some(r);
						r
					}
					None => {
						smoothed_rate = Some(current_rate);
						current_rate
					}
				};
				if rate > 0.0 {
					let remaining = (total - done) as f64 / rate;
					// Pad 20% conservative
					let conservative = remaining * 1.2;
					let rounded = round_eta_up(conservative);
					format!("~{} remaining", format_duration_secs(rounded))
				} else {
					"--".to_string()
				}
			};
			// Pad to 80 chars to overwrite any longer previous line
			let line = format!("  {}: {}/{} ({}%) -- {}", label, done, total, pct, eta_str);
			eprint!("\r{:<80}", line);
		}
	})
}

/// Stop a progress monitor and print the final summary line with elapsed time.
pub fn stop_progress_monitor(
	monitor: JoinHandle<()>,
	label: &str,
	total: usize,
	start: Instant,
) {
	monitor.abort();
	let elapsed_secs = start.elapsed().as_secs();
	let time_str = format_duration_secs(elapsed_secs);
	// Clear entire line first to avoid leftover characters from longer progress text
	eprint!("\r{:width$}\r", "", width = 80);
	eprint!("  {}: {}/{} (100%) -- done in {}\n", label, total, total, time_str);
}

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
	let char_timeout = Duration::from_millis(crate::transport::DEFAULT_CHAR_TIMEOUT_MS);
	let char_attempts = crate::transport::DEFAULT_CHAR_ATTEMPTS;
	println!("Reachability pre-check ({} resolvers, {} attempts, {} ms timeout)...",
		resolvers.len(), char_attempts, char_timeout.as_millis());

	let semaphore = std::sync::Arc::new(Semaphore::new(32));
	let phase0_total = resolvers.len();
	let phase0_done = Arc::new(AtomicUsize::new(0));
	let phase0_start = Instant::now();
	let monitor = spawn_progress_monitor(
		"Reachability".to_string(), phase0_done.clone(), phase0_total, phase0_start,
	);

	let mut reachability_handles = Vec::new();
	for (i, resolver) in resolvers.iter().enumerate() {
		let addr = resolver.addr;
		let sem = semaphore.clone();
		let ct = char_timeout;
		let attempts = char_attempts;
		let done = phase0_done.clone();

		reachability_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
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
			done.fetch_add(1, Ordering::Relaxed);
			(i, any_fast)
		}));
	}

	let mut reachable = vec![false; resolvers.len()];
	for handle in reachability_handles {
		match handle.await {
			Ok((idx, is_reachable)) => {
				reachable[idx] = is_reachable;
			}
			Err(e) => {
				eprintln!("Warning: reachability check failed: {}", e);
			}
		}
	}
	stop_progress_monitor(monitor, "Reachability", phase0_total, phase0_start);

	// Log reachability results and remove unreachable resolvers
	let before = resolvers.len();
	for (i, resolver) in resolvers.iter().enumerate() {
		if !reachable[i] {
			config.telemetry.log_sidelined(
				&resolver.addr.ip().to_string(), "reachability_precheck", 0,
			);
			let class = resolver_class(resolver);
			if class != "public" {
				println!("  {} {} ({}) -- sidelined (reachability precheck)",
					class, resolver.label, resolver.addr.ip());
			}
		}
	}
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
	let phase1_total = resolvers.len();
	let phase1_done = Arc::new(AtomicUsize::new(0));
	let phase1_start = Instant::now();
	let monitor = spawn_progress_monitor(
		"NXDOMAIN check".to_string(), phase1_done.clone(), phase1_total, phase1_start,
	);

	let mut handles = Vec::new();
	for (i, resolver) in resolvers.iter().enumerate() {
		let addr = resolver.addr;
		let sem = semaphore.clone();
		let tm = timeout;
		let domains = nxdomain_domains.to_vec();
		let done = phase1_done.clone();

		handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let intercepts = check_nxdomain_interception(addr, tm, &domains).await;
			done.fetch_add(1, Ordering::Relaxed);
			(i, intercepts)
		}));
	}

	let mut nxdomain_intercept_count = 0usize;
	for handle in handles {
		match handle.await {
			Ok((idx, intercepts)) => {
				resolvers[idx].intercepts_nxdomain = intercepts;
				if intercepts { nxdomain_intercept_count += 1; }
			}
			Err(e) => {
				eprintln!("Warning: characterization task failed: {}", e);
			}
		}
	}
	stop_progress_monitor(monitor, "NXDOMAIN check", phase1_total, phase1_start);
	println!("  {} intercept NXDOMAIN, {} OK",
		nxdomain_intercept_count, resolvers.len() - nxdomain_intercept_count);
	println!();

	// Phase 2: Check rebinding protection
	println!("Checking DNS rebinding protection ({} resolvers)...", resolvers.len());
	let phase2_total = resolvers.len();
	let phase2_done = Arc::new(AtomicUsize::new(0));
	let phase2_start = Instant::now();
	let monitor = spawn_progress_monitor(
		"Rebinding check".to_string(), phase2_done.clone(), phase2_total, phase2_start,
	);

	let mut rebind_handles = Vec::new();
	for (i, resolver) in resolvers.iter().enumerate() {
		let addr = resolver.addr;
		let sem = semaphore.clone();
		let tm = timeout;
		let done = phase2_done.clone();

		rebind_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let protection = check_rebinding_protection(addr, tm).await;
			done.fetch_add(1, Ordering::Relaxed);
			(i, protection)
		}));
	}

	let mut rebind_protected = 0usize;
	let mut rebind_not = 0usize;
	let mut rebind_unknown = 0usize;
	for handle in rebind_handles {
		match handle.await {
			Ok((idx, protection)) => {
				resolvers[idx].rebinding_protection = protection;
				match protection {
					Some(true) => rebind_protected += 1,
					Some(false) => rebind_not += 1,
					None => rebind_unknown += 1,
				}
			}
			Err(e) => {
				eprintln!("Warning: rebinding check failed: {}", e);
			}
		}
	}
	stop_progress_monitor(monitor, "Rebinding check", phase2_total, phase2_start);
	println!("  {} protected, {} not protected, {} unknown",
		rebind_protected, rebind_not, rebind_unknown);
	println!();

	// Phase 3: Check DNSSEC validation
	println!("Checking DNSSEC validation ({} resolvers)...", resolvers.len());
	let phase3_total = resolvers.len();
	let phase3_done = Arc::new(AtomicUsize::new(0));
	let phase3_start = Instant::now();
	let monitor = spawn_progress_monitor(
		"DNSSEC check".to_string(), phase3_done.clone(), phase3_total, phase3_start,
	);

	let mut dnssec_handles = Vec::new();
	for (i, resolver) in resolvers.iter().enumerate() {
		let addr = resolver.addr;
		let sem = semaphore.clone();
		let tm = timeout;
		let done = phase3_done.clone();

		dnssec_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let validates = check_dnssec_validation(addr, tm).await;
			done.fetch_add(1, Ordering::Relaxed);
			(i, validates)
		}));
	}

	let mut dnssec_validates = 0usize;
	let mut dnssec_not = 0usize;
	let mut dnssec_unknown = 0usize;
	for handle in dnssec_handles {
		match handle.await {
			Ok((idx, validates)) => {
				resolvers[idx].validates_dnssec = validates;
				match validates {
					Some(true) => dnssec_validates += 1,
					Some(false) => dnssec_not += 1,
					None => dnssec_unknown += 1,
				}
			}
			Err(e) => {
				eprintln!("Warning: DNSSEC validation check failed: {}", e);
			}
		}
	}
	stop_progress_monitor(monitor, "DNSSEC check", phase3_total, phase3_start);
	println!("  {} validate, {} do not validate, {} unknown",
		dnssec_validates, dnssec_not, dnssec_unknown);

	// Log characterization summary per resolver
	for resolver in resolvers.iter() {
		let nxdomain_str = if resolver.intercepts_nxdomain { "intercepts" } else { "ok" };
		let rebinding_str = match resolver.rebinding_protection {
			Some(true) => "protected",
			Some(false) => "not_protected",
			None => "unknown",
		};
		let dnssec_str = match resolver.validates_dnssec {
			Some(true) => "validates",
			Some(false) => "no",
			None => "unknown",
		};
		let class = resolver_class(resolver);
		config.telemetry.log_characterization(
			&resolver.addr.ip().to_string(), &resolver.label, class,
			true, nxdomain_str, rebinding_str, dnssec_str,
		);
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
	println!("Discovery mode: screening {} resolvers...", resolvers.len());

	// Pick discovery domains from the first category with enough entries
	let discovery_domains: &[String] = categories.values()
		.find(|domains| domains.len() >= 5)
		.or_else(|| categories.values().next())
		.map(|v| v.as_slice())
		.unwrap_or(&[]);

	// Phase 1: fast parallel reachability screen (1 query per resolver)
	let screen_timeout_udp = Duration::from_millis(SCREEN_TIMEOUT_MS);
	let screen_timeout_tls = Duration::from_millis(SCREEN_TLS_TIMEOUT_MS);
	let screen_domain = discovery_domains.first()
		.map(|s| s.as_str())
		.unwrap_or("google.com");
	// Discovery uses higher concurrency since it's a simple reachability check
	let discovery_concurrency = DISCOVERY_CONCURRENCY.max(config.max_inflight);
	let semaphore = std::sync::Arc::new(Semaphore::new(discovery_concurrency));

	let screen_total = resolvers.len();
	let screen_done = Arc::new(AtomicUsize::new(0));
	let screen_start = Instant::now();
	let monitor = spawn_progress_monitor(
		"Screening".to_string(), screen_done.clone(), screen_total, screen_start,
	);

	let mut screen_handles = Vec::new();
	for resolver in resolvers {
		let sem = semaphore.clone();
		// Discovery is a reachability check only -- skip DNSSEC DO bit
		// to keep queries small and avoid larger EDNS responses under load
		let dnssec = false;
		let domain = screen_domain.to_string();
		let resolver_clone = resolver.clone();
		let doh_clients = doh_clients.clone();
		let done = screen_done.clone();
		// DoT/DoH need longer timeout for TCP + TLS handshake
		let screen_timeout = match &resolver.transport {
			DnsTransport::Udp => screen_timeout_udp,
			_ => screen_timeout_tls,
		};

		screen_handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let txid: u16 = rand::random();
			let query_bytes = match build_query(
				&domain, QueryType::A, txid, dnssec,
			) {
				Ok(b) => b,
				Err(_) => {
					done.fetch_add(1, Ordering::Relaxed);
					return (resolver_clone, false, true);
				}
			};
			let result = dispatch_query(
				&resolver_clone, &query_bytes, screen_timeout,
				txid, &domain, QueryType::A, &doh_clients,
			).await;
			done.fetch_add(1, Ordering::Relaxed);
			(resolver_clone, result.success, result.timeout)
		}));
	}

	let mut survivors = Vec::new();
	let mut panicked = 0usize;
	let mut timed_out = 0usize;
	let mut failed_fast = 0usize;
	for handle in screen_handles {
		match handle.await {
			Ok((resolver, reachable, was_timeout)) => {
				let class = resolver_class(&resolver);
				if reachable {
					config.telemetry.log_discovery(
						&resolver.addr.ip().to_string(), &resolver.label,
						class, true, "reachable",
					);
					survivors.push(resolver);
				} else {
					let reason = if was_timeout { "timeout" } else { "connect_failed" };
					config.telemetry.log_discovery(
						&resolver.addr.ip().to_string(), &resolver.label,
						class, false, reason,
					);
					// Print private/system resolver failures to stdout
					if class != "public" {
						println!("  {} {} ({}) -- {}",
							class, resolver.label, resolver.addr.ip(), reason);
					}
					if was_timeout { timed_out += 1; } else { failed_fast += 1; }
				}
			}
			Err(_) => {
				panicked += 1;
			}
		}
	}
	stop_progress_monitor(monitor, "Screening", screen_total, screen_start);

	let unreachable = resolvers.len() - survivors.len();
	println!(
		"  Screen: {}/{} resolvers reachable ({} unreachable, dropped)",
		survivors.len(), resolvers.len(), unreachable,
	);
	// Diagnostic breakdown of failures
	if timed_out > 0 || failed_fast > 0 || panicked > 0 {
		println!(
			"  Failures: {} timed out, {} connect failed, {} panicked",
			timed_out, failed_fast, panicked,
		);
	}

	config.telemetry.log_pipeline("discovery_reachable", survivors.len());
	Ok(survivors)
}

/// Run a lightweight qualification pass to select finalists for medium mode.
///
/// Sends a small number of queries per resolver (cached + uncached + NXDOMAIN)
/// and scores by median latency, variance, timeout rate, and correctness.
/// Returns the most promising candidates up to the finalist budget.
pub async fn run_qualification(
	resolvers: &[ResolverConfig],
	categories: &std::collections::BTreeMap<String, Vec<String>>,
	config: &BenchmarkConfig,
	doh_clients: &DohClientPool,
) -> Result<Vec<ResolverConfig>> {
	println!("Qualification pass: scoring {} resolvers...", resolvers.len());

	// Build a small domain set: up to 3 cached, 5 uncached, 2 from other categories
	let mut qual_domains: Vec<String> = Vec::new();
	if let Some(cached) = categories.get("cached") {
		qual_domains.extend(cached.iter().take(3).cloned());
	}
	if let Some(uncached) = categories.get("uncached") {
		qual_domains.extend(uncached.iter().take(5).cloned());
	}
	// Add 2 from any other category for diversity
	for (name, domains) in categories {
		if name != "cached" && name != "uncached" && qual_domains.len() < 12 {
			qual_domains.extend(domains.iter().take(2).cloned());
		}
	}
	if qual_domains.is_empty() {
		// Fallback if no categories available
		qual_domains.push("google.com".to_string());
	}

	println!("  Using {} qualification domains", qual_domains.len());

	let semaphore = std::sync::Arc::new(Semaphore::new(config.max_inflight));
	let timeout = config.timeout;

	// Total tasks = resolvers * domains
	let qual_total = resolvers.len() * qual_domains.len();
	let qual_done = Arc::new(AtomicUsize::new(0));
	let qual_start = Instant::now();
	let monitor = spawn_progress_monitor(
		"Qualifying".to_string(), qual_done.clone(), qual_total, qual_start,
	);

	// Run qualification queries
	let mut handles = Vec::new();
	for resolver in resolvers {
		for domain in &qual_domains {
			let sem = semaphore.clone();
			let resolver_clone = resolver.clone();
			let dnssec = config.dnssec;
			let domain_clone = domain.clone();
			let doh_clients = doh_clients.clone();
			let done = qual_done.clone();

			handles.push(tokio::spawn(async move {
				let _permit = sem.acquire().await.unwrap();
				let txid: u16 = rand::random();
				let query_bytes = match build_query(
					&domain_clone, QueryType::A, txid, dnssec,
				) {
					Ok(b) => b,
					Err(_) => {
						done.fetch_add(1, Ordering::Relaxed);
						return (resolver_clone.addr.ip().to_string(), None, true);
					}
				};
				let result = dispatch_query(
					&resolver_clone, &query_bytes, timeout,
					txid, &domain_clone, QueryType::A, &doh_clients,
				).await;
				done.fetch_add(1, Ordering::Relaxed);
				if result.success {
					let latency_ms = result.latency.as_secs_f64() * 1000.0;
					(resolver_clone.addr.ip().to_string(), Some(latency_ms), false)
				} else {
					(resolver_clone.addr.ip().to_string(), None, result.timeout)
				}
			}));
		}
	}

	// Collect results per resolver
	let mut resolver_data: HashMap<String, (Vec<f64>, usize, usize)> = HashMap::new();
	for handle in handles {
		if let Ok((ip, latency, is_timeout)) = handle.await {
			let entry = resolver_data.entry(ip).or_insert_with(|| (Vec::new(), 0, 0));
			entry.1 += 1; // total queries
			if let Some(lat) = latency {
				entry.0.push(lat);
			}
			if is_timeout {
				entry.2 += 1; // timeout count
			}
		}
	}
	stop_progress_monitor(monitor, "Qualifying", qual_total, qual_start);

	// Score each resolver: lower is better
	// Score = median_latency + (variance_penalty) + (timeout_penalty)
	let timeout_penalty_ms = config.timeout.as_millis() as f64;
	let mut scored: Vec<(String, f64)> = resolver_data.iter()
		.map(|(ip, (latencies, total, timeouts))| {
			let timeout_rate = *timeouts as f64 / *total as f64;
			if latencies.is_empty() {
				// No successful queries — worst score
				return (ip.clone(), f64::INFINITY);
			}
			let mut sorted = latencies.clone();
			sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
			let median = sorted[sorted.len() / 2];
			// Variance: standard deviation
			let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
			let variance = sorted.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / sorted.len() as f64;
			let stddev = variance.sqrt();
			// Combined score: median + stddev + timeout penalty
			let score = median + stddev + (timeout_rate * timeout_penalty_ms);
			(ip.clone(), score)
		})
		.collect();

	// Sort by score (lower = better)
	scored.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

	// Promote up to the benchmark budget, ranked by qualification score
	let budget = crate::transport::DEFAULT_MEDIUM_BUDGET;
	let resolver_labels: HashMap<String, String> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), r.label.clone()))
		.collect();
	let promote_count = scored.iter()
		.filter(|(_, s)| s.is_finite())
		.count()
		.min(budget);
	// Build class map for telemetry tagging
	let resolver_classes: HashMap<String, &str> = resolvers.iter()
		.map(|r| (r.addr.ip().to_string(), resolver_class(r)))
		.collect();
	// Log all candidates with promoted flag
	for (i, (ip, score)) in scored.iter().enumerate() {
		let label = resolver_labels.get(ip).map(|s| s.as_str()).unwrap_or("");
		let class = resolver_classes.get(ip).copied().unwrap_or("public");
		let promoted = score.is_finite() && i < promote_count;
		config.telemetry.log_qualification(ip, label, class, *score, promoted);
		// Print private/system resolver qualification to stdout
		if class != "public" {
			let status = if promoted { "promoted" } else { "not promoted" };
			println!("  {} {} ({}) -- score {:.1}, {} (rank {}/{})",
				class, label, ip, score, status, i + 1, scored.len());
		}
	}
	let finalist_ips: std::collections::HashSet<String> = scored.into_iter()
		.filter(|(_, s)| s.is_finite())
		.take(promote_count)
		.map(|(ip, _)| ip)
		.collect();

	let finalists: Vec<ResolverConfig> = resolvers.iter()
		.filter(|r| finalist_ips.contains(&r.addr.ip().to_string()))
		.cloned()
		.collect();

	println!("  Promoted {} finalists from {} candidates (budget {})",
		finalists.len(), resolvers.len(), budget);

	Ok(finalists)
}

/// Run a staged elimination benchmark for slow mode.
///
/// Runs 2-round blocks with progressive purging of the weaker half
/// until the finalist floor is reached, then runs remaining rounds
/// on the final set.
pub async fn run_staged_benchmark(
	resolvers: &[ResolverConfig],
	categories: &std::collections::BTreeMap<String, Vec<String>>,
	config: &BenchmarkConfig,
	doh_clients: &DohClientPool,
) -> Result<Vec<ScoredResolver>> {
	let purge_ratio = crate::transport::DEFAULT_SLOW_PURGE_RATIO;
	let finalist_min = crate::transport::DEFAULT_SLOW_FINALIST_MIN;
	let total_rounds = config.rounds;

	println!("Staged elimination: {} resolvers, {} total rounds, purge {:.0}% per stage",
		resolvers.len(), total_rounds, purge_ratio * 100.0);

	let mut active_resolvers = resolvers.to_vec();
	let mut round_offset = 0u32;

	while round_offset < total_rounds {
		// Run 2-round block (or remaining rounds if fewer left)
		let block_rounds = 2.min(total_rounds - round_offset);

		// Build a config for this block
		let mut block_config = config.clone();
		block_config.rounds = block_rounds;

		println!("  Stage: {} resolvers, rounds {}-{}",
			active_resolvers.len(),
			round_offset + 1,
			round_offset + block_rounds);

		let results = run_benchmark(
			&active_resolvers, categories, &block_config, doh_clients,
		).await?;

		round_offset += block_rounds;

		// Check if we should purge
		let target_count = (active_resolvers.len() as f64 * (1.0 - purge_ratio)) as usize;
		if round_offset < total_rounds && active_resolvers.len() > finalist_min && target_count >= finalist_min {
			// Keep the top half by score
			let keep_count = target_count.max(finalist_min);
			let keep_ips: std::collections::HashSet<String> = results.iter()
				.take(keep_count)
				.map(|r| r.stats.addr.clone())
				.collect();

			let before = active_resolvers.len();
			active_resolvers.retain(|r| keep_ips.contains(&r.addr.ip().to_string()));
			println!("  Purged: {} -> {} resolvers (removed weaker half)",
				before, active_resolvers.len());
		} else if round_offset >= total_rounds {
			// Final block — return these results
			return Ok(results);
		}
	}

	// Final benchmark on remaining resolvers
	let mut final_config = config.clone();
	final_config.rounds = 2.min(total_rounds.saturating_sub(round_offset));
	if final_config.rounds > 0 {
		let results = run_benchmark(
			&active_resolvers, categories, &final_config, doh_clients,
		).await?;
		return Ok(results);
	}

	// Shouldn't reach here, but run a final pass just in case
	run_benchmark(&active_resolvers, categories, config, doh_clients).await
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
		let round_start = std::time::Instant::now();
		// Filter out sidelined resolvers for this round
		let mut round_tasks = tasks.clone();
		if !sidelined.is_empty() {
			round_tasks.retain(|t| !sidelined.contains(&t.resolver.addr.ip().to_string()));
		}
		round_tasks.shuffle(&mut rng);

		let round_total = round_tasks.len();
		let completed_count = Arc::new(AtomicUsize::new(0));

		// Progress monitor with ETA
		let round_label = format!("Round {}/{}", round + 1, config.rounds);
		let monitor = spawn_progress_monitor(
			round_label.clone(), completed_count.clone(), round_total, round_start,
		);

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

		// Stop progress monitor and print final line with elapsed time
		stop_progress_monitor(monitor, &round_label, round_total, round_start);

		// Log round completion to telemetry
		let round_failures = all_results.iter()
			.filter(|(t, r)| {
				let ip = t.resolver.addr.ip().to_string();
				!sidelined.contains(&ip) && !r.success
			})
			.count();
		config.telemetry.log_round_complete(round + 1, round_total, round_failures);

		// Log per-resolver stats for this round
		{
			let mut round_stats: HashMap<String, (usize, usize, usize, Vec<f64>)> = HashMap::new();
			for (task, result) in &all_results {
				let ip = task.resolver.addr.ip().to_string();
				if sidelined.contains(&ip) { continue; }
				// Only count results from the current round
				let entry = round_stats.entry(ip).or_insert((0, 0, 0, Vec::new()));
				entry.0 += 1; // queries
				if result.success {
					entry.1 += 1; // successes
					entry.3.push(result.latency.as_secs_f64() * 1000.0);
				}
				if result.timeout { entry.2 += 1; } // timeouts
			}
			for (ip, (queries, successes, timeouts, latencies)) in &round_stats {
				let p50 = if latencies.is_empty() {
					0.0
				} else {
					let mut sorted = latencies.clone();
					sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
					sorted[sorted.len() / 2]
				};
				config.telemetry.log_round_resolver(
					round + 1, ip, *queries, *successes, *timeouts, p50,
				);
			}
		}

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
