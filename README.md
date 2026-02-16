# rust-dns-benchmark

A CLI tool that benchmarks DNS resolver performance over UDP. It measures cached (warm), uncached (cold), and TLD-diverse query latency, validates DNS responses, detects NXDOMAIN interception, and ranks resolvers by a composite score with statistical tie detection. Useful for choosing the fastest and most trustworthy DNS resolver for your network.

## Quick start

```bash
cargo build --release
cargo run --release
```

This benchmarks 89 public resolvers from [resolvers.txt](resolvers.txt) with default settings (auto-discovery screens them down to the fastest 50 for your network). See [docs/USAGE.md](docs/USAGE.md) for all CLI options and examples.

## Features

- **Warm, cold, and TLD benchmarking**: measures cached latency, uncached latency across real domains, and TLD infrastructure diversity.
- **NXDOMAIN interception detection**: probes resolvers for DNS hijacking of nonexistent domains.
- **Statistical tie detection**: groups resolvers with overlapping uncertainty bands using MAD-based analysis.
- **DNSSEC timing mode**: measures latency with the DNSSEC OK (DO) bit set.
- **Discovery mode**: prefilters large resolver lists down to the top N fastest before full benchmarking.
- **89 default resolvers**: ships with a curated [resolvers.txt](resolvers.txt) covering major providers and privacy-focused alternatives, auto-filtered to the fastest for your location.
- **CSV export**: detailed per-resolver statistics for further analysis.

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md): requirements and build steps.
- [docs/USAGE.md](docs/USAGE.md): CLI options, resolver formats, scoring formula, and examples.
- [docs/CHANGELOG.md](docs/CHANGELOG.md): chronological record of changes.
- [docs/AUTHORS.md](docs/AUTHORS.md): maintainers and contributors.
- [docs/REPO_STYLE.md](docs/REPO_STYLE.md): repo-level organization and conventions.
- [docs/PYTHON_STYLE.md](docs/PYTHON_STYLE.md): Python conventions for test infrastructure.
- [docs/MARKDOWN_STYLE.md](docs/MARKDOWN_STYLE.md): Markdown formatting rules.

## License

GPLv3. See [LICENSE](LICENSE).

## Author

Neil Voss, <https://bsky.app/profile/neilvosslab.bsky.social>
