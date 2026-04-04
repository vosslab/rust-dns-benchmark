use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// JSONL telemetry logger for benchmark runs.
/// Writes one JSON object per line to dns_benchmark.jsonl.
#[derive(Clone)]
pub struct TelemetryLog {
	file: Arc<Mutex<Option<File>>>,
}

impl std::fmt::Debug for TelemetryLog {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let enabled = self.file.lock().map(|g| g.is_some()).unwrap_or(false);
		write!(f, "TelemetryLog(enabled={})", enabled)
	}
}

//============================================
fn timestamp_iso() -> String {
	// Format current time as ISO 8601
	let now = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.unwrap_or_default();
	let secs = now.as_secs();
	// Simple UTC timestamp without chrono dependency
	let days = secs / 86400;
	let time_secs = secs % 86400;
	let hours = time_secs / 3600;
	let minutes = (time_secs % 3600) / 60;
	let seconds = time_secs % 60;
	// Approximate date from days since epoch (good enough for logging)
	let (year, month, day) = days_to_ymd(days);
	format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hours, minutes, seconds)
}

//============================================
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
	// Convert days since Unix epoch to (year, month, day)
	let mut y = 1970;
	let mut remaining = days;
	loop {
		let days_in_year = if is_leap(y) { 366 } else { 365 };
		if remaining < days_in_year {
			break;
		}
		remaining -= days_in_year;
		y += 1;
	}
	let month_days: [u64; 12] = if is_leap(y) {
		[31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
	} else {
		[31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
	};
	let mut m = 0;
	for md in &month_days {
		if remaining < *md {
			break;
		}
		remaining -= *md;
		m += 1;
	}
	(y, m + 1, remaining + 1)
}

//============================================
fn is_leap(y: u64) -> bool {
	(y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

//============================================
/// Escape a string for JSON output (handles quotes, backslashes, control chars).
fn json_escape(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		match c {
			'"' => out.push_str("\\\""),
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			'\r' => out.push_str("\\r"),
			'\t' => out.push_str("\\t"),
			c if (c as u32) < 0x20 => {
				out.push_str(&format!("\\u{:04x}", c as u32));
			}
			_ => out.push(c),
		}
	}
	out
}

impl TelemetryLog {
	//============================================
	/// Create a new telemetry log. Returns a disabled logger if path is None.
	pub fn new(enabled: bool) -> Self {
		let file = if enabled {
			OpenOptions::new()
				.create(true)
				.write(true)
				.truncate(true)
				.open("dns_benchmark.jsonl")
				.ok()
		} else {
			None
		};
		TelemetryLog {
			file: Arc::new(Mutex::new(file)),
		}
	}

	//============================================
	/// Write a raw JSON line to the log.
	pub fn write_line(&self, json_line: &str) {
		if let Ok(mut guard) = self.file.lock() {
			if let Some(ref mut f) = *guard {
				let _ = writeln!(f, "{}", json_line);
			}
		}
	}

	//============================================
	/// Log benchmark configuration at startup.
	pub fn log_config(&self, rounds: u32, spacing_ms: u64, level: &str, resolver_count: usize) {
		let ts = timestamp_iso();
		let line = format!(
			r#"{{"event":"config","timestamp":"{}","rounds":{},"spacing_ms":{},"level":"{}","resolver_count":{}}}"#,
			ts, rounds, spacing_ms, json_escape(level), resolver_count
		);
		self.write_line(&line);
	}

	//============================================
	/// Log a pipeline stage (loaded, reachable, top_n_filtered, etc.).
	pub fn log_pipeline(&self, stage: &str, count: usize) {
		let ts = timestamp_iso();
		let line = format!(
			r#"{{"event":"pipeline","timestamp":"{}","stage":"{}","count":{}}}"#,
			ts, json_escape(stage), count
		);
		self.write_line(&line);
	}

	//============================================
	/// Log a sidelined resolver.
	pub fn log_sidelined(&self, resolver: &str, reason: &str, round: u32) {
		let ts = timestamp_iso();
		let line = format!(
			r#"{{"event":"sidelined","timestamp":"{}","resolver":"{}","reason":"{}","round":{}}}"#,
			ts, json_escape(resolver), json_escape(reason), round
		);
		self.write_line(&line);
	}

	//============================================
	/// Log completion of a benchmark round.
	pub fn log_round_complete(&self, round: u32, queries: usize, failures: usize) {
		let ts = timestamp_iso();
		let line = format!(
			r#"{{"event":"round_complete","timestamp":"{}","round":{},"queries":{},"failures":{}}}"#,
			ts, round, queries, failures
		);
		self.write_line(&line);
	}

	//============================================
	/// Log a discovery screening outcome for a single resolver.
	pub fn log_discovery(&self, resolver: &str, label: &str, class: &str,
		passed: bool, reason: &str, latency_ms: f64,
	) {
		let ts = timestamp_iso();
		let line = format!(
			r#"{{"event":"discovery","timestamp":"{}","resolver":"{}","label":"{}","class":"{}","passed":{},"reason":"{}","latency_ms":{:.1}}}"#,
			ts, json_escape(resolver), json_escape(label), json_escape(class),
			passed, json_escape(reason), latency_ms
		);
		self.write_line(&line);
	}

	//============================================
	/// Log a characterization result for a single resolver.
	pub fn log_characterization(&self, resolver: &str, label: &str, class: &str,
		reachable: bool, latency_ms: f64, attempts_used: u32, successes: u32,
		nxdomain: &str, rebinding: &str, dnssec: &str,
	) {
		let ts = timestamp_iso();
		let line = format!(
			r#"{{"event":"characterization","timestamp":"{}","resolver":"{}","label":"{}","class":"{}","reachable":{},"latency_ms":{:.1},"attempts_used":{},"successes":{},"nxdomain":"{}","rebinding":"{}","dnssec":"{}"}}"#,
			ts, json_escape(resolver), json_escape(label), json_escape(class), reachable,
			latency_ms, attempts_used, successes,
			json_escape(nxdomain), json_escape(rebinding), json_escape(dnssec)
		);
		self.write_line(&line);
	}

	//============================================
	/// Log a qualification score for a single resolver.
	pub fn log_qualification(&self, resolver: &str, label: &str, class: &str,
		score: f64, promoted: bool, p50_ms: f64, p95_ms: f64, timeout_rate: f64,
	) {
		let ts = timestamp_iso();
		let line = format!(
			r#"{{"event":"qualification","timestamp":"{}","resolver":"{}","label":"{}","class":"{}","score":{:.1},"promoted":{},"p50_ms":{:.1},"p95_ms":{:.1},"timeout_rate":{:.3}}}"#,
			ts, json_escape(resolver), json_escape(label), json_escape(class),
			score, promoted, p50_ms, p95_ms, timeout_rate
		);
		self.write_line(&line);
	}

	//============================================
	/// Log a per-resolver phase timing.
	pub fn log_phase(&self, phase: &str, elapsed_secs: u64, before: usize, after: usize) {
		let ts = timestamp_iso();
		let line = format!(
			r#"{{"event":"phase","timestamp":"{}","phase":"{}","elapsed_secs":{},"before":{},"after":{}}}"#,
			ts, json_escape(phase), elapsed_secs, before, after
		);
		self.write_line(&line);
	}

	//============================================
	/// Log per-resolver per-round summary stats after each round.
	pub fn log_round_resolver(&self, round: u32, resolver: &str,
		queries: usize, successes: usize, timeouts: usize,
		p50_ms: f64, mean_ms: f64, stddev_ms: f64,
	) {
		let ts = timestamp_iso();
		let success_rate = if queries > 0 { successes as f64 / queries as f64 * 100.0 } else { 0.0 };
		let line = format!(
			r#"{{"event":"round_resolver","timestamp":"{}","round":{},"resolver":"{}","queries":{},"successes":{},"timeouts":{},"success_rate":{:.1},"p50_ms":{:.1},"mean_ms":{:.1},"stddev_ms":{:.1}}}"#,
			ts, round, json_escape(resolver), queries, successes, timeouts,
			success_rate, p50_ms, mean_ms, stddev_ms
		);
		self.write_line(&line);
	}

	//============================================
	/// Log a final result entry with full per-category breakdown.
	pub fn log_result_detail(&self, rank: usize, resolver: &str, label: &str,
		score: f64, success_rate: f64, categories_json: &str,
	) {
		let ts = timestamp_iso();
		let line = format!(
			r#"{{"event":"result","timestamp":"{}","rank":{},"resolver":"{}","label":"{}","score":{:.1},"success_rate":{:.1},"categories":{}}}"#,
			ts, rank, json_escape(resolver), json_escape(label), score, success_rate, categories_json
		);
		self.write_line(&line);
	}

}
