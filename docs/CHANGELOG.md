# Changelog

## 2026-04-03

### Additions and New Features
- Added `query_domains.csv` with data-driven domain categories (cached, uncached, tld, dotcom, dnssec) replacing hardcoded per-category functions
- Added `--no-test` flag to print config summary and exit without running benchmark (useful with `--exhaustive` to verify resolver loading)
- Added resolver deduplication by IP address after all sources are loaded, fixing count mismatch between CSV download and displayed total

### Behavior or Interface Changes
- Exhaustive mode now skips discovery Phase 2 (top-N cut), keeping all reachable resolvers for the full benchmark instead of hard-cutting to top 50
- Applied CLI argument minimalism round 2: reduced from 14 flags to 7. Removed `--scan`, `--aaaa`, `--dnssec`, `--seed`, `--no-system-resolvers`, `--sort`, `--query-domains`. Moved removed settings to compile-time constants in `src/transport.rs`
- AAAA queries and DNSSEC are now always enabled (hardcoded on)
- System resolvers from /etc/resolv.conf are now always included
- Sort order hardcoded to "score"
- `--scan` mode removed; `--exhaustive` subsumes it
- Restructured config display into three clear sections: "Resolvers under test", "Query domains", and "Timing and options"
- Renamed domain categories from warm/cold to cached/uncached for clarity
- Results table columns are now dynamic based on loaded categories instead of hardcoded warm/cold/tld/dotcom/dnssec
- CSV output columns are now dynamic based on loaded categories
- Overall score now averages all categories with data instead of hardcoded warm+cold+dotcom formula
- Removed `query_dnssec_domains` field from `BenchmarkConfig`
- Replaced 20-field `ResolverAggregation` struct with generic `BTreeMap<String, CategoryAgg>`
- Replaced per-category fields in `ResolverStats` with `BTreeMap<String, SetStats>`

### Behavior or Interface Changes
- Applied CLI argument minimalism: reduced from 35 flags to 12. Removed 23 rarely-changed flags (domain file overrides, timeout/concurrency/spacing tuning, discovery controls, protocol exclusions, sideline tuning, characterization params, telemetry toggle). Hardcoded sensible defaults as constants in `src/transport.rs`
- IPv6, DoH, and DoT built-in resolvers are now always included (removed `--no-ipv6-resolvers`, `--no-doh-resolvers`, `--no-dot-resolvers`)
- TLD and dotcom benchmarks always run (removed `--no-tld`, `--no-dotcom`)
- System resolvers always pinned to top of results (removed `--no-pin-system`)
- Mid-benchmark sidelining always enabled at 500ms threshold (removed `--no-sideline`, `--sideline-ms`)
- Discovery mode is fully automatic: activates when >20 resolvers, always on for scan/exhaustive (removed `--discover`, `--no-discover`, `--top`)
- Telemetry logging always enabled (removed `--no-log`)
- Updated [docs/USAGE.md](docs/USAGE.md) to reflect simplified CLI

### Additions and New Features
- Added `--exhaustive` flag for full global DNS benchmark: auto-downloads ~63K nameservers from public-dns.info, combines with all built-in lists (IPv4, IPv6, DoH, DoT), forces discovery and 30 rounds
- Added JSONL telemetry log (`dns_benchmark.jsonl`): logs config, pipeline stages, sidelined resolvers, round completions, and final results. Enabled by default, disable with `--no-log`
- `--scan` mode now includes built-in resolver lists (Google, Cloudflare, Quad9, etc.) alongside the US scan list, fixing missing well-known resolvers from results

### Behavior or Interface Changes
- Changed default query spacing from 5ms to 25ms with random jitter (0-50%), reducing load on DNS servers. GRC uses 20ms; our new default of 25-37ms is gentler
- Pipeline summary now shows `--top N` filter value so users understand why resolvers were filtered (e.g., "After discovery: 50 (--top 50 filter applied)")
- `resolvers/scan_global.txt` and `dns_benchmark.jsonl` added to `.gitignore` (downloaded/generated files)

## 2026-04-02

### Additions and New Features
- Expanded built-in resolver lists: moved to `resolvers/` directory with 4 separate files
  - `resolvers/resolvers.txt`: ~130 IPv4 UDP resolvers (was 89), added Mullvad, Gcore, UncensoredDNS, NTT, Comcast, and 20+ more providers
  - `resolvers/resolvers_ipv6.txt`: ~45 IPv6 resolvers (new) covering all major providers
  - `resolvers/resolvers_doh.txt`: ~80 DoH resolvers (new) including Cloudflare, Google, Quad9, Mullvad, ControlD, CIRA, regional endpoints
  - `resolvers/resolvers_dot.txt`: ~60 DoT resolvers (new) with SNI hostnames for all major providers
- Added `--no-ipv6-resolvers`, `--no-doh-resolvers`, `--no-dot-resolvers` flags to selectively exclude protocol categories
- Added dotcom-specific lookup timing: 20 `.com` domains measured separately to benchmark dotcom TLD resolution
  - New `--dotcom-domains` and `--no-dotcom` CLI flags
  - Dotcom score factored into overall ranking (3-way average with warm and cold)
  - DotCom p50 column in results table and CSV
- Added DNSSEC-signed domain benchmarking: 15 known DNSSEC-signed domains benchmarked when `--dnssec` is enabled
  - New `--dnssec-domains` CLI flag for custom DNSSEC domain list
  - DNSSEC p50 column in results table and CSV when enabled
- Added v2-style characterization sidelining: resolvers get up to 10 attempts (configurable) to reply within 50ms (configurable) before being sidelined
  - New `--char-timeout` (default 50ms) and `--char-attempts` (default 10) CLI flags
  - Unreachable resolvers removed before NXDOMAIN/rebinding/DNSSEC characterization
- Added resolver pipeline summary showing counts at each stage: initial, post-discovery, post-characterization, final
- Added `--sort dotcom` option for sorting results by dotcom p50 latency
- Expanded conclusions section with DNSSEC validation warnings, slow-network detection, and IPv4 vs IPv6 side-by-side comparison for same-provider pairs
- Structured exit codes expanded: 0-8 covering file not found, no IPs, too many resolvers, no connectivity, lost connectivity, log file errors
- Added `--scan` flag for massive-scale testing: loads ~11,549 US public DNS resolvers from bundled `resolvers/scan_us.txt` (sourced from public-dns.info), forces discovery mode, and runs 30 rounds for thorough benchmarking

### Behavior or Interface Changes
- Resolver files moved from repo root to `resolvers/` directory; loader searches `resolvers/` first, then CWD, then exe dir
- `run_characterization()` now takes `&BenchmarkConfig` instead of bare timeout for access to char_timeout/char_attempts
- Overall score now averages warm + cold + dotcom (3-way) when dotcom is enabled; was warm + cold only
- Default resolver list includes IPv6, DoH, and DoT resolvers (use `--no-*-resolvers` flags to exclude)

- Added colored output to results table: score/latency green/yellow/red by threshold, success rate colored, NXDOMAIN/DNSSEC/rebind status colored, top-3 ranks bold green
- Added `--save-resolvers` CLI flag to export surviving resolver list to a file after benchmark
- Added conclusions summary printed after results table: fastest resolver, system resolver ranking, performance comparison, NXDOMAIN interception warnings
- Added real-time progress indicator during benchmark rounds showing queries completed and percentage
- Added explicit exit codes for scripting: 0=success, 1=file not found, 4=no resolvers, 5=no connectivity
- Added DNS over TLS (DoT) transport support via `tls://` prefix (e.g., `tls://1.1.1.1`)
- Added DNS over HTTPS (DoH) transport support via `https://` prefix (e.g., `https://1.1.1.1/dns-query`)
- Added transport dispatch layer: `dispatch_query()` routes queries to UDP, DoT, or DoH based on resolver config
- Added `DnsTransport` enum (`Udp`, `Dot`, `Doh`) to `ResolverConfig` for transport-aware resolver handling
- Added protocol column to results table when mixed transports are present; transport always in CSV output
- Added mid-benchmark sidelining: slow resolvers (>80% timeouts or p50 > threshold) are dropped between rounds
- Added `--sideline-ms` flag (default: 500) and `--no-sideline` flag to control sidelining behavior
- Added reverse DNS (PTR) lookups for all resolver IPs during characterization phase
- PTR hostnames shown in results table next to resolver label when available
- Added DNS rebinding protection detection: checks if resolvers filter private/loopback IPs from responses
- Added DNSSEC validation verification: queries `dnssec-failed.org` (intentionally broken DNSSEC) to detect validating resolvers
- DNSSEC validation and rebinding protection columns added to results table and CSV output
- Added filtering of resolvers with <50% success rate to reduce noise in results
- Added `--sort` flag to sort results by: `score` (default), `warm`, `cold`, `tld`, or `name`
- Added `--pin-system` flag to pin system resolvers (from `/etc/resolv.conf`) to the top of results
- Added `is_system` tracking through `ResolverConfig`, `ResolverStats`, and `ScoredResolver` to identify system resolvers
- System resolvers are marked with `[sys]` in the output table
- Sort mode and pin status are shown in the configuration summary

### Behavior or Interface Changes
- Version bumped to 26.04.0
- Default mode now loads both master resolver list AND system resolvers for comprehensive testing
- System resolvers now included by default (use `--no-system-resolvers` to opt out, replaces `--system-resolvers`)
- System resolvers are deduplicated against the master list to avoid duplicate entries
- System resolvers now pinned to top by default (use `--no-pin-system` to opt out, replaces `--pin-system`)
- New dependencies: `reqwest` (DoH), `tokio-rustls`/`rustls`/`webpki-roots` (DoT), `hickory-resolver` (PTR lookups)
- DoT uses per-query TLS connections (cold-start measurement); DoH uses shared HTTP/2 connections (realistic usage)
- Resolvers with <50% success rate are now filtered from results by default

### Fixes and Maintenance
- Fixed all clippy warnings (loop patterns, redundant bindings, collapsed if-let)
- Fixed dead resolvers (0% success) sorting to rank #1 instead of last; `set_score()` now returns infinity when `success_count == 0` (`src/stats.rs`)
- Wired up `--nxdomain-domains` CLI flag to `run_characterization()` so custom NXDOMAIN probe domains are now used instead of a single hardcoded domain (`src/dns.rs`, `src/bench.rs`, `src/main.rs`)
- Connected `default_nxdomain_domains()` (10 `.invalid` probe domains) as the default when no custom file is provided
- Refactored `check_nxdomain_interception()` to accept a domain list and probe each domain, improving detection coverage
- Removed unused `CharacterizationResult` struct from `src/transport.rs` and simplified `run_characterization()` return type to `()`
- Moved `#[allow(dead_code)]` annotations from struct level to individual unused fields (`answer_count` in `DnsResponse`, `domain`/`query_type`/`rcode` in `QueryResult`)
- Added inline documentation for the scoring formula in `src/stats.rs::set_score()`
- Replaced O(n^2) uncertainty lookup in `src/bench.rs` with HashMap-based O(n) lookup

---

## 2026-02-16 (performance and reliability fixes)

### Parallel characterization and discovery
- Rewrote `run_characterization()` in `src/bench.rs` to run concurrently with semaphore of 32 (was sequential)
- Rewrote `run_discovery()` in `src/bench.rs` to run both phases (fast screen + quick benchmark) in parallel
- Restructured `src/main.rs` flow: discovery now runs BEFORE characterization to avoid wasting time on resolvers that will be dropped
- Fixed network saturation bug: sequential probing of 107 resolvers exhausted local network before benchmark could run

### CLI default changes
- Reduced default timeout from 5000ms to 2000ms in `src/cli.rs`
- Increased default `--top` from 10 to 50 in `src/cli.rs`
- Added `--no-discover` flag to disable auto-discovery
- Added `--max-resolver-ms` flag (default 1000) to drop resolvers with warm p50 above threshold
- Auto-discovery enabled when resolver list exceeds 20 entries

### Bug fixes
- Fixed error path in `run_benchmark()`: used `task.resolver.label.clone()` as resolver key instead of `task.resolver.addr.ip().to_string()`, causing inconsistent keying between success and error paths
- Increased UDP receive buffer from 512 to 4096 bytes for EDNS-extended DNS responses
- Added post-benchmark latency filtering and re-ranking in `src/main.rs`

### Cold domain fixes
- Replaced non-resolving cold domains (biblioteca.bn.br, nlk.or.kr, registry.io) with verified alternatives (ibge.gov.br, snu.ac.kr, crates.io)
- Replaced non-resolving TLD domain (u-tokyo.ac.jp) with keio.ac.jp
- All 50 cold domains and 32 TLD domains now verified to resolve with A records

### Output improvements
- Added "IP Address" column to results table and CSV output
- Consolidated table from 6 latency columns to 3 (Warm p50, Cold p50, TLD p50); p95 detail preserved in CSV
- Added `addr` field to `ResolverStats` in `src/stats.rs`
- Truncated resolver list display in config summary when >20 resolvers (shows first 5 + last 2)

### Documentation
- Updated [docs/USAGE.md](USAGE.md) with new flags, auto-discovery description, and updated defaults
- Updated [docs/CHANGELOG.md](CHANGELOG.md) with all changes

---

## 2026-02-16 (v2 upgrades)

### Phase 1: real cold domains + NXDOMAIN interception detection
- Replaced 50 fake cold domains with 50 real, resolvable domains across diverse TLDs (.gov, .edu, .ch, .au, .jp, .br, .fi, .se, etc.)
- Added `default_nxdomain_domains()` returning 10 .invalid TLD domains for interception testing
- Extended `DnsResponse` with `has_a_records` field for answer introspection
- Added `check_nxdomain_interception()` async function in `src/dns.rs`
- Added `CharacterizationResult` struct in `src/transport.rs`
- Added `intercepts_nxdomain` field to `ResolverConfig`
- Added `run_characterization()` to `src/bench.rs` -- runs before benchmark, probes each resolver
- Added "NXDOMAIN" column to results table ("OK" or "Intercepts")
- Added `intercepts_nxdomain` field to CSV output
- Added `--nxdomain-domains` CLI flag for custom NXDOMAIN test domains
- Added `intercepts_nxdomain` to `ResolverStats` and `ScoredResolver`

### Phase 2: TLD hop metric
- Added `default_tld_domains()` returning 32 domains spanning 25+ unique TLDs
- Added TLD domain tasks with `set_name: "tld"` in benchmark engine
- Added `tld: Option<SetStats>` to `ResolverStats`
- Added "TLD p50" and "TLD p95" columns to results table
- Added `tld_*` columns to CSV output
- Added `--tld-domains` and `--no-tld` CLI flags

### Phase 3: statistical tie detection
- Added `compute_uncertainty()` using MAD (median absolute deviation) scaled by 1.4826
- Added `detect_ties()` that groups resolvers with overlapping uncertainty bands
- Added `tie_group: Option<String>` to `ScoredResolver` (e.g. "1-3")
- Rank column shows shared rank labels when resolvers are tied
- Note printed below table when ties are detected

### Phase 4: DNSSEC timing mode
- Added `dnssec: bool` parameter to `build_query()` -- sets DO bit via EDNS
- Added `--dnssec` CLI flag (default off)
- Added `dnssec` field to `BenchmarkConfig`
- Passes dnssec flag through all query paths

### Phase 5: discovery mode
- Added `run_discovery()` in `src/bench.rs` -- two-phase prefilter (fast screen + quick benchmark)
- Added `--discover` and `--top` CLI flags
- Discovery mode screens large resolver lists and keeps only the top N

### Resolver list curation
- Created `resolvers.txt` with 89 public DNS resolvers with inline labels
- Removed 18 resolvers that timeout or respond over 1 second (Mullvad, AlternateDNS, DNS0-EU, UncensoredDNS, Quad101, Digitale Gesellschaft, AppliedPrivacy, FDN-France, puntCAT, LibreDNS, Digitalcourage)
- Updated `src/resolver.rs` to load defaults from `resolvers.txt`
- Added `parse_resolver_line()` for parsing inline `# Label` comments
- `default_resolvers()` tries `resolvers.txt` first, falls back to hardcoded 4

### Documentation
- Updated [README.md](../README.md) with feature list and resolver count

### Test coverage
- 34 unit tests (up from 21): domains (7), dns (6), resolver (8), stats (12), transport (1)

## 2026-02-16

- Created `Cargo.toml` with dependencies: tokio, hickory-proto, clap, rand, comfy-table, csv, anyhow, thiserror
- Created `VERSION` file (26.02.0)
- Updated `.gitignore` to include `/target`
- Created `src/main.rs` -- entry point wiring CLI, resolvers, domains, benchmark, and output
- Created `src/cli.rs` -- clap derive CLI argument parsing
- Created `src/transport.rs` -- shared types (ResolverConfig, QueryType, QueryResult, BenchmarkConfig)
- Created `src/dns.rs` -- DNS query building and response parsing via hickory-proto (5 unit tests)
- Created `src/stats.rs` -- percentile, mean, stddev, set scoring, and resolver ranking (8 unit tests)
- Created `src/resolver.rs` -- resolver address parsing, file reading, system resolvers, defaults (6 unit tests)
- Created `src/domains.rs` -- default warm/cold domain lists and file reading (2 unit tests)
- Created `src/output.rs` -- comfy-table results display and CSV file output
- Created `src/bench.rs` -- async benchmark engine with per-task UDP sockets, semaphore concurrency, seeded shuffling
- Created `docs/INSTALL.md` with requirements and build steps
- Created `docs/USAGE.md` with CLI options, resolver formats, scoring formula, and examples
- Updated `README.md` to be concise with links to docs
