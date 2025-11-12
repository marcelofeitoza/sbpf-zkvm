# Solana BPF zkVM - Build Automation
#
# Common tasks for building, testing, and running the zkVM demo

# Default recipe - show available commands
default:
    @just --list

# Initialize project - fetch and build submodules
init:
    @echo "🔧 Initializing project..."
    git submodule update --init --recursive
    @echo "✓ Submodules initialized"

# Build all workspace crates
build:
    @echo "🔨 Building workspace..."
    cargo build --workspace
    @echo "✓ Build complete"

# Build in release mode
build-release:
    @echo "🔨 Building workspace (release)..."
    cargo build --workspace --release
    @echo "✓ Release build complete"

# Build the BPF counter program
build-bpf:
    @echo "🔨 Building BPF counter program..."
    cd examples/counter-program && \
    cargo build --target bpfel-unknown-unknown --release
    @echo "✓ BPF program built"
    @echo "   Output: examples/counter-program/target/bpfel-unknown-unknown/release/counter_program.so"

# Run all tests
test:
    @echo "🧪 Running tests..."
    cargo test --workspace
    @echo "✓ All tests passed"

# Run tests with output
test-verbose:
    @echo "🧪 Running tests (verbose)..."
    cargo test --workspace -- --nocapture
    @echo "✓ All tests passed"

# Run the end-to-end demo
demo:
    @echo "🎬 Running demo..."
    cargo run --example demo
    @echo "✓ Demo complete"

# Run demo with verbose logging
demo-verbose:
    @echo "🎬 Running demo (verbose)..."
    RUST_LOG=debug cargo run --example demo
    @echo "✓ Demo complete"

# Check code with clippy
clippy:
    @echo "📎 Running clippy..."
    cargo clippy --workspace --all-targets -- -D warnings
    @echo "✓ Clippy passed"

# Format code
fmt:
    @echo "✨ Formatting code..."
    cargo fmt --all
    @echo "✓ Code formatted"

# Check formatting
fmt-check:
    @echo "✨ Checking code format..."
    cargo fmt --all -- --check
    @echo "✓ Format check passed"

# Clean build artifacts
clean:
    @echo "🧹 Cleaning build artifacts..."
    cargo clean
    rm -rf examples/counter-program/target
    @echo "✓ Clean complete"

# Full check - format, clippy, test, build
check: fmt-check clippy test build
    @echo "✅ All checks passed!"

# Setup development environment
setup: init
    @echo "🚀 Setting up development environment..."
    rustup target add bpfel-unknown-unknown
    rustup component add rustfmt clippy
    @echo "✓ Development environment ready"

# Show project statistics
stats:
    @echo "📊 Project Statistics:"
    @echo ""
    @echo "Lines of code:"
    @find . -name '*.rs' -not -path './target/*' -not -path './deps/*' | xargs wc -l | tail -1
    @echo ""
    @echo "Crates:"
    @find . -name 'Cargo.toml' -not -path './target/*' -not -path './deps/*' | wc -l
    @echo ""
    @echo "Tests:"
    @grep -r "#\[test\]" --include="*.rs" --exclude-dir=target --exclude-dir=deps | wc -l
