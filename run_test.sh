#!/bin/sh

cargo build
cargo test
cargo run -- --level exhaustive --no-test
sleep 2
reset

cargo run -- --level medium
sleep 30
cargo run -- --level slow
