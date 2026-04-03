#!/bin/sh

cargo build && cargo test && cargo run -- --level exhaustive --no-test && cargo run -- --level medium
