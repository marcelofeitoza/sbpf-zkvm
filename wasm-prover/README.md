# WASM zkVM Prover

Browser-based zero-knowledge prover for Solana BPF programs. Generates Halo2 proofs entirely client-side.

## Build

```bash
# Install wasm-pack if needed
cargo install wasm-pack

# Build WASM
cd wasm-prover
wasm-pack build --target web --out-dir pkg
```

## Run

```bash
cd www
ln -sf ../pkg pkg
python3 -m http.server 8080
# Open http://localhost:8080
```

## What it does

1. Executes a minimal BPF counter program in WASM
2. Generates execution trace (stays in WASM memory)
3. Creates Halo2 proof (~3KB)
4. Verifies proof in browser

Private witness data never leaves the browser.
