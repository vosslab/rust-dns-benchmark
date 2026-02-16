# Changelog

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
- Updated `README.md` with project description, usage examples, CLI options, and scoring formula
