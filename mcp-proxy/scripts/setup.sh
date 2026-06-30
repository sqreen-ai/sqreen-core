#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust toolchain not found. Install it with:"
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  echo "Then restart your shell or run: source \"\$HOME/.cargo/env\""
  exit 1
fi

if [[ ! -f .env && -f .env.example ]]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

echo "Using $(rustc --version)"
echo "Building mcp-proxy..."
cargo build
echo "Running tests..."
cargo test
echo "Done. Run with:"
echo "  cargo run -- -- run <command> [args...]"
