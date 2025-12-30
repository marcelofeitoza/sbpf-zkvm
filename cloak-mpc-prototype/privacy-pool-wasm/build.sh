#!/bin/bash
set -e

echo "🔨 Building Privacy Pool WASM Prover..."

# Build WASM
wasm-pack build --target web --out-dir www/pkg

echo "✅ Build complete!"
echo ""
echo "To run the demo:"
echo "  cd www && python3 -m http.server 8081"
echo "  Open http://localhost:8081"


