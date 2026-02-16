# Install

This is a Rust CLI binary. "Installed" means the `rust-dns-benchmark` binary is built and runnable.

## Requirements

- Rust toolchain (rustc + cargo). Tested with Rust 1.93; edition 2021 is the minimum.
- Network access to DNS resolvers over UDP port 53.

## Install steps

```bash
git clone <repo-url>
cd rust-dns-benchmark
cargo build --release
```

The binary is placed at `target/release/rust-dns-benchmark`.

## Verify install

```bash
cargo run --release -- --help
```

This prints the CLI usage text. If it prints options and exits cleanly, the build is working.
