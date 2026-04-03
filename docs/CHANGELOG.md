# Changelog

## 2026-04-02

### Additions and New Features
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
