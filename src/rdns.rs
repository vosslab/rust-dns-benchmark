use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use crate::bench::{spawn_progress_monitor, stop_progress_monitor};
use crate::record::ResolverRecord;

/// Perform reverse DNS (PTR) lookups for all resolver records.
/// Updates each record's resolver.ptr_name field.
pub async fn resolve_ptr_names(
	records: &mut [ResolverRecord],
	timeout: Duration,
) {
	println!("Resolving PTR records ({} resolvers)...", records.len());

	let total = records.len();
	let completed = Arc::new(AtomicUsize::new(0));
	let start = Instant::now();
	let monitor = spawn_progress_monitor(
		"PTR lookup".to_string(), completed.clone(), total, start,
	);

	let semaphore = std::sync::Arc::new(Semaphore::new(16));
	let mut handles = Vec::new();

	for (i, rec) in records.iter().enumerate() {
		let ip = rec.resolver.addr.ip();
		let sem = semaphore.clone();
		let tm = timeout;
		let done = completed.clone();

		handles.push(tokio::spawn(async move {
			let _permit = sem.acquire().await.unwrap();
			let ptr_name = lookup_ptr(ip, tm).await;
			done.fetch_add(1, Ordering::Relaxed);
			(i, ptr_name)
		}));
	}

	let mut resolved_count = 0usize;
	for handle in handles {
		match handle.await {
			Ok((idx, ptr_name)) => {
				if ptr_name.is_some() { resolved_count += 1; }
				records[idx].resolver.ptr_name = ptr_name;
			}
			Err(e) => {
				eprintln!("Warning: PTR lookup task failed: {}", e);
			}
		}
	}
	stop_progress_monitor(monitor, "PTR lookup", total, start);
	println!("  {} resolved, {} no PTR record", resolved_count, total - resolved_count);

	println!();
}

//============================================
/// Look up the PTR record for a single IP address.
///
/// Returns the hostname if found, None otherwise.
async fn lookup_ptr(ip: IpAddr, timeout: Duration) -> Option<String> {
	// Build the PTR query domain from the IP
	let ptr_domain = match ip {
		IpAddr::V4(v4) => {
			let octets = v4.octets();
			format!("{}.{}.{}.{}.in-addr.arpa",
				octets[3], octets[2], octets[1], octets[0])
		}
		IpAddr::V6(v6) => {
			// Build nibble-reversed .ip6.arpa domain
			let segments = v6.segments();
			let mut nibbles = String::new();
			for seg in segments.iter().rev() {
				for shift in [0, 4, 8, 12] {
					let nibble = (seg >> shift) & 0xf;
					if !nibbles.is_empty() {
						nibbles.push('.');
					}
					nibbles.push_str(&format!("{:x}", nibble));
				}
			}
			format!("{}.ip6.arpa", nibbles)
		}
	};

	// Use a UDP query to the system's default resolver for PTR lookup
	let txid: u16 = rand::random();
	let query_bytes = match crate::dns::build_ptr_query(&ptr_domain, txid) {
		Ok(b) => b,
		Err(_) => return None,
	};

	// Query system resolver (use first nameserver from /etc/resolv.conf)
	let system_resolver = get_system_resolver()?;

	let bind_addr = if system_resolver.is_ipv4() {
		"0.0.0.0:0"
	} else {
		"[::]:0"
	};
	let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
		Ok(s) => s,
		Err(_) => return None,
	};

	if socket.send_to(&query_bytes, system_resolver).await.is_err() {
		return None;
	}

	let mut buf = vec![0u8; 4096];
	match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
		Ok(Ok((len, _))) => {
			crate::dns::parse_ptr_response(&buf[..len], txid)
		}
		_ => None,
	}
}

/// Get the first system resolver address from /etc/resolv.conf.
fn get_system_resolver() -> Option<std::net::SocketAddr> {
	let content = std::fs::read_to_string("/etc/resolv.conf").ok()?;
	for line in content.lines() {
		let trimmed = line.trim();
		if trimmed.starts_with("nameserver") {
			let parts: Vec<&str> = trimmed.split_whitespace().collect();
			if parts.len() >= 2 {
				if let Ok(ip) = parts[1].parse::<IpAddr>() {
					return Some(std::net::SocketAddr::new(ip, 53));
				}
			}
		}
	}
	None
}
