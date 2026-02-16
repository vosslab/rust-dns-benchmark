# rust-dns-benchmark

A CLI tool that benchmarks DNS resolver performance over UDP, measuring both cached (warm) and uncached (cold) query latency.

## Features

- Benchmarks multiple DNS resolvers in parallel
- Measures warm (cached) and cold (uncached) query latency separately
- Scores resolvers using a formula that balances median latency, tail latency, and reliability
- Validates DNS responses (txid matching, rcode checking), not just speed
- Supports custom resolver lists, domain lists, and CSV output
- Reproducible results via seeded randomization

## Quick start

```bash
# Build
cargo build --release

# Run with defaults (Cloudflare, Google, Quad9, OpenDNS)
cargo run --release

# Benchmark specific resolvers
cargo run --release -- -r 1.1.1.1 -r 8.8.8.8 -r 9.9.9.9

# Custom rounds, timeout, and CSV output
cargo run --release -- -n 5 -t 3000 -o results.csv

# Include system resolvers from /etc/resolv.conf
cargo run --release -- --system-resolvers
```

## CLI options

| Flag | Description | Default |
| --- | --- | --- |
| `-r, --resolver` | Resolver address (repeatable) | Defaults if none given |
| `-f, --resolver-file` | File with resolver addresses | |
| `--warm-domains` | File with warm (cached) domains | Built-in list of 10 |
| `--cold-domains` | File with cold (uncached) domains | Built-in list of 50 |
| `-n, --rounds` | Number of benchmark rounds | 3 |
| `-t, --timeout` | Query timeout in milliseconds | 5000 |
| `-c, --concurrency` | Max concurrent in-flight queries | 64 |
| `--spacing` | Inter-query spacing in milliseconds | 5 |
| `--aaaa` | Also query AAAA records | off |
| `-o, --output` | CSV output file path | |
| `-s, --seed` | Random seed for reproducibility | |
| `--system-resolvers` | Include system resolvers | off |

## Scoring

Each resolver gets separate warm and cold set scores:

```
set_score = p50 + 0.5 * (p95 - p50) + timeout_penalty * timeout_rate
```

The overall score is the average of warm and cold set scores. Lower is better.

## License

GPLv3. See [LICENSE](LICENSE).

## Author

Neil Voss, <https://bsky.app/profile/neilvosslab.bsky.social>
