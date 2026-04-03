# Usage

Benchmark DNS resolver latency over UDP, DoT, and DoH. The tool sends queries for cached, uncached, TLD-diverse, dotcom, and DNSSEC-signed domains, measures response times, validates responses, detects NXDOMAIN interception, and ranks resolvers by a composite score with statistical tie detection.

## Quick start

```bash
# Run with default built-in resolvers
cargo run --release

# Exhaustive mode: test all global public resolvers (recommended)
cargo run --release -- --exhaustive

# Benchmark specific resolvers
cargo run --release -- -r 1.1.1.1 -r 8.8.8.8 -r 9.9.9.9

# Custom rounds and CSV output
cargo run --release -- -n 5 -o results.csv
```

## CLI options

| Flag | Description | Default |
| --- | --- | --- |
| `-r, --resolver` | Resolver address (repeatable) | Built-in defaults |
| `-f, --resolver-file` | File with resolver addresses | |
| `-n, --rounds` | Number of benchmark rounds | 3 |
| `-o, --output` | CSV output file path | |
| `--save-resolvers` | Save surviving resolver list to file | |
| `--exhaustive` | Load ALL global resolvers, benchmark with 30 rounds | off |
| `--no-test` | Print config and exit without running benchmark | off |

Run `cargo run --release -- --help` for the built-in help text.

### Compile-time defaults

Settings removed from the CLI are compile-time constants in `src/transport.rs`:

| Constant | Value | Description |
| --- | --- | --- |
| `DEFAULT_QUERY_AAAA` | true | Always query AAAA records |
| `DEFAULT_DNSSEC` | true | Always enable DNSSEC |
| `DEFAULT_INCLUDE_SYSTEM_RESOLVERS` | true | Always include /etc/resolv.conf |
| `DEFAULT_SORT` | "score" | Sort results by score |
| `DEFAULT_EXHAUSTIVE_ROUNDS` | 30 | Rounds in exhaustive mode |

## Examples

```bash
# Exhaustive global benchmark with CSV output
cargo run --release -- --exhaustive -o results.csv

# Save the surviving resolver list for later use
cargo run --release -- --exhaustive --save-resolvers survivors.txt

# Dry run: verify config without benchmarking
cargo run --release -- --exhaustive --no-test

# Benchmark specific resolvers with more rounds
cargo run --release -- -r 1.1.1.1 -r 8.8.8.8 -n 10
```

## Inputs and outputs

### Resolver addresses

Resolvers can be specified in several formats:

- `1.1.1.1` -- IPv4, default port 53
- `1.1.1.1:5353` -- IPv4 with custom port
- `2606:4700::1111` -- bare IPv6, default port 53
- `[2606:4700::1111]:53` -- bracketed IPv6 with port

When no resolvers are provided, the tool loads built-in lists of IPv4, IPv6, DoH, and DoT resolvers. System resolvers from `/etc/resolv.conf` are always included. When more than 20 resolvers are loaded, discovery mode activates automatically to prefilter down to the top 50 before the full benchmark.

Resolver files support inline labels with `#` comments:

```
1.1.1.1  # Cloudflare
8.8.8.8  # Google
```

### Domain lists

All domain lists are built-in and not user-configurable:

- **Cached domains** (10): popular sites likely to be cached.
- **Uncached domains** (50): real, resolvable domains across diverse TLDs unlikely to be cached.
- **TLD domains** (33): one domain per TLD for measuring resolution across diverse TLD infrastructure.
- **Dotcom domains** (20): popular .com domains for measuring dotcom-specific performance.
- **DNSSEC domains**: DNSSEC-signed domains for validation benchmarking (always included).

### Output

- **Table**: printed to stdout with rank, resolver, score, per-category p50/p95, success rate, and NXDOMAIN interception status.
- **CSV** (`-o`): detailed per-resolver stats including mean, stddev, success/timeout counts, set scores, interception status, and tie group.

## Features

### NXDOMAIN interception detection

Before the benchmark, each resolver is probed with queries for known-nonexistent domains (.invalid TLD per RFC 2606). If a resolver returns A records for these domains, it is flagged as "Intercepts" in the NXDOMAIN column. This detects ad-redirect resolvers that hijack failed lookups.

### TLD diversity measurement

The TLD hop metric measures resolver performance across many different top-level domains (.com, .org, .gov, .uk, .de, .jp, etc.). TLD p50 and p95 columns show how well a resolver handles diverse TLD infrastructure.

### Statistical tie detection

Resolvers with overlapping uncertainty bands are grouped as ties. Uncertainty is computed using MAD (median absolute deviation) scaled by 1.4826 for normal distribution consistency. Tied resolvers show a shared rank label (e.g. "1-3") instead of individual ranks.

### DNSSEC timing

The DO (DNSSEC OK) bit is set on all queries via EDNS. This measures the latency impact of DNSSEC validation. Latencies may be slightly higher due to additional cryptographic verification.

### Discovery mode

Discovery mode prefilters a large resolver list in two phases:

1. **Fast screen**: 2 queries per resolver with a strict 1-second timeout. Unreachable resolvers are discarded.
2. **Quick benchmark**: 1 round of cached-only queries on survivors. The top 50 by cached p50 latency proceed to the full benchmark.

Discovery activates automatically when the resolver list exceeds 20 entries. In `--exhaustive` mode, discovery is always enabled. After the full benchmark, resolvers with cached p50 above 1000 ms are filtered from results.

## Scoring

Each resolver gets separate category scores:

```
set_score = p50 + 0.5 * (p95 - p50) + timeout_penalty * timeout_rate
```

- `p50` and `p95` are the median and 95th percentile latencies in milliseconds.
- `timeout_penalty` equals the configured timeout value.
- `timeout_rate` is the fraction of queries that timed out.

The overall score is the average of all category scores. Lower is better.
