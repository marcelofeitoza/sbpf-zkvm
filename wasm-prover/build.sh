#!/bin/bash
# Build script for WASM zkVM Prover

set -e

echo "🔨 Building WASM zkVM Prover..."

# Check for wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "❌ wasm-pack not found. Install with:"
    echo "   cargo install wasm-pack"
    exit 1
fi

# Build WASM with web target
echo "📦 Running wasm-pack..."
wasm-pack build --target web --out-dir pkg

echo "✓ WASM build complete!"
echo ""
echo "To run locally:"
echo "  cd www"
echo "  python3 -m http.server 8080"
echo "  # Open http://localhost:8080"
echo ""
echo "Or with any static file server that supports WASM MIME type."

