# Usage

Benchmark DNS resolver latency over UDP. The tool sends queries for warm (cached), cold (uncached), and TLD-diverse domains, measures response times, validates responses, detects NXDOMAIN interception, and ranks resolvers by a composite score with statistical tie detection.

## Quick start

```bash
# Run with default resolvers (loaded from resolvers.txt, 89 public resolvers)
cargo run --release

# Benchmark specific resolvers
cargo run --release -- -r 1.1.1.1 -r 8.8.8.8 -r 9.9.9.9

# Custom rounds, timeout, and CSV output
cargo run --release -- -n 5 -t 3000 -o results.csv
```

## CLI options

| Flag | Description | Default |
| --- | --- | --- |
| `-r, --resolver` | Resolver address (repeatable) | Defaults if none given |
| `-f, --resolver-file` | File with resolver addresses | |
| `--warm-domains` | File with warm (cached) domains | Built-in list of 10 |
| `--cold-domains` | File with cold (uncached) domains | Built-in list of 50 |
| `--tld-domains` | File with TLD-diverse domains | Built-in list of 32 |
| `--nxdomain-domains` | File with NXDOMAIN test domains | |
| `--no-tld` | Disable TLD diversity measurement | off (TLD on) |
| `-n, --rounds` | Number of benchmark rounds | 3 |
| `-t, --timeout` | Query timeout in milliseconds | 2000 |
| `-c, --concurrency` | Max concurrent in-flight queries | 64 |
| `--spacing` | Inter-query spacing in milliseconds | 5 |
| `--aaaa` | Also query AAAA records | off |
| `--dnssec` | Enable DNSSEC (set DO bit on all queries) | off |
| `--discover` | Enable discovery mode to prefilter resolvers | auto (on when >20 resolvers) |
| `--no-discover` | Disable auto-discovery | off |
| `--top` | Number of top resolvers to keep in discovery | 50 |
| `--max-resolver-ms` | Drop resolvers with warm p50 above this threshold (ms) | 1000 |
| `-o, --output` | CSV output file path | |
| `-s, --seed` | Random seed for reproducibility | |
| `--system-resolvers` | Include system resolvers | off |

Run `cargo run --release -- --help` for the built-in help text.

## Examples

```bash
# Include system resolvers from /etc/resolv.conf alongside custom ones
cargo run --release -- --system-resolvers -r 1.1.1.1

# Reproducible benchmark with a fixed seed
cargo run --release -- -s 42 -n 3

# Use custom domain lists
cargo run --release -- --warm-domains my_warm.txt --cold-domains my_cold.txt

# DNSSEC timing mode (sets DO bit on all queries)
cargo run --release -- --dnssec -r 1.1.1.1 -n 1

# Discovery mode: screen a large list down to the top 5
cargo run --release -- --discover -f resolvers.txt --top 5 -n 2

# Disable TLD measurement for faster runs
cargo run --release -- --no-tld -n 1
```

## Inputs and outputs

### Resolver addresses

Resolvers can be specified in several formats:

- `1.1.1.1` -- IPv4, default port 53
- `1.1.1.1:5353` -- IPv4 with custom port
- `2606:4700::1111` -- bare IPv6, default port 53
- `[2606:4700::1111]:53` -- bracketed IPv6 with port

When no resolvers are provided, the tool loads from [resolvers.txt](../resolvers.txt) (89 public resolvers). If that file is not found, it falls back to Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9), and OpenDNS (208.67.222.222). When more than 20 resolvers are loaded, discovery mode activates automatically to prefilter down to the fastest before the full benchmark.

Resolver files support inline labels with `#` comments:

```
1.1.1.1  # Cloudflare
8.8.8.8  # Google
```

### Domain lists

- **Warm domains**: popular sites likely to be cached. Built-in list has 10 domains.
- **Cold domains**: real, resolvable domains across diverse TLDs unlikely to be cached. Built-in list has 50 domains spanning .gov, .edu, .ch, .au, .jp, .br, and more.
- **TLD domains**: one domain per TLD for measuring resolution across diverse TLD infrastructure. Built-in list has 32 domains across 25+ unique TLDs.

Custom domain files use one domain per line. Blank lines and `#` comments are skipped.

### Output

- **Table**: printed to stdout with rank, resolver, score, warm/cold p50/p95, TLD p50/p95, success rate, and NXDOMAIN interception status.
- **CSV** (`-o`): detailed per-resolver stats including mean, stddev, success/timeout counts, set scores, interception status, and tie group.

## Features

### NXDOMAIN interception detection

Before the benchmark, each resolver is probed with queries for known-nonexistent domains (.invalid TLD per RFC 2606). If a resolver returns A records for these domains, it is flagged as "Intercepts" in the NXDOMAIN column. This detects ad-redirect resolvers that hijack failed lookups.

### TLD diversity measurement

The TLD hop metric measures resolver performance across many different top-level domains (.com, .org, .gov, .uk, .de, .jp, etc.). TLD p50 and p95 columns show how well a resolver handles diverse TLD infrastructure. Disable with `--no-tld`.

### Statistical tie detection

Resolvers with overlapping uncertainty bands are grouped as ties. Uncertainty is computed using MAD (median absolute deviation) scaled by 1.4826 for normal distribution consistency. Tied resolvers show a shared rank label (e.g. "1-3") instead of individual ranks.

### DNSSEC timing mode

With `--dnssec`, the DO (DNSSEC OK) bit is set on all queries via EDNS. This measures the latency impact of DNSSEC validation. Latencies may be slightly higher due to the additional cryptographic verification.

### Discovery mode

Discovery mode prefilters a large resolver list in two phases:

1. **Fast screen**: 2 queries per resolver with a strict 1-second timeout. Unreachable resolvers are discarded.
2. **Quick benchmark**: 1 round of warm-only queries on survivors. The top N (default 50, set with `--top`) by warm p50 latency proceed to the full benchmark.

Discovery activates automatically when the resolver list exceeds 20 entries. Force it on with `--discover` or disable it with `--no-discover`. After the full benchmark, resolvers with warm p50 above `--max-resolver-ms` (default 1000) are filtered from results.

## Scoring

Each resolver gets separate warm and cold set scores:

```
set_score = p50 + 0.5 * (p95 - p50) + timeout_penalty * timeout_rate
```

- `p50` and `p95` are the median and 95th percentile latencies in milliseconds.
- `timeout_penalty` equals the configured timeout value.
- `timeout_rate` is the fraction of queries that timed out.

The overall score is the average of warm and cold set scores. Lower is better. TLD scores are reported separately as additional context.
