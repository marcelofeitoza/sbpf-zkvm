# Cloak MPC Prototype

A production-ready privacy pool implementation for Solana using Groth16 zkSNARKs with secure MPC trusted setup.

## 🏗️ Architecture

```
cloak-mpc-prototype/
├── mpc-ceremony/          # MPC trusted setup tool
├── privacy-pool/          # On-chain Solana program (Pinocchio)
├── privacy-pool-wasm/     # Browser-side proof generator (WASM)
├── privacy-pool-demo/     # Next.js demo application
├── no-std-svm-merkle-tree/# no_std Merkle tree library
└── scripts/               # Integration test scripts
```

## 🔐 Security Features

| Feature | Description |
|---------|-------------|
| **MPC Ceremony** | Secure trusted setup - only 1 honest participant needed |
| **Poseidon Hash** | ZK-friendly, collision-resistant hash function |
| **Domain Separation** | Pool ID bound to nullifier prevents cross-pool attacks |
| **Double-Spend Protection** | Nullifiers tracked on-chain |
| **Recipient Binding** | Proof locks funds to specific recipient |
| **Range Checks** | 64-bit amount validation in circuit |
| **Front-Running Protection** | Commit-reveal scheme for withdrawals |
| **Emergency Pause** | Admin can halt pool operations |

## 🚀 Quick Start

### Prerequisites

```bash
# Rust toolchain
rustup install stable
rustup target add wasm32-unknown-unknown

# Solana CLI
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"

# WASM tools
cargo install wasm-pack

# Node.js (for demo)
# Install via https://nodejs.org or nvm
```

### Run Full Integration Test

```bash
# Run the complete test (MPC ceremony → build → on-chain test)
./scripts/test-privacy-pool.sh

# Skip WASM build (faster)
./scripts/test-privacy-pool.sh --skip-wasm

# Skip on-chain tests (no devnet SOL needed)
./scripts/test-privacy-pool.sh --skip-tests
```

### Individual Components

```bash
# Build MPC ceremony tool
cd mpc-ceremony && cargo build --release

# Build privacy pool program
cd privacy-pool && cargo build-sbf

# Build WASM prover
cd privacy-pool-wasm && wasm-pack build --target web --out-dir www/pkg

# Run Next.js demo
cd privacy-pool-demo && npm install && npm run dev
```

## 🎲 MPC Ceremony

The MPC ceremony generates secure proving/verifying keys for Groth16.

### Security Model

- **1-of-N honest**: If at least ONE participant is honest and destroys their entropy, the ceremony is secure
- **Recommended**: 3+ participants from independent parties

### Running a Ceremony

```bash
# 1. Initialize (first party)
mpc-ceremony init --pool-id "YOUR_POOL_PROGRAM_ID" -o ceremony_init.bin

# 2. Party 1 contributes
mpc-ceremony contribute -i ceremony_init.bin -o ceremony_p1.bin --name "Party-1"

# 3. Party 2 contributes
mpc-ceremony contribute -i ceremony_p1.bin -o ceremony_p2.bin --name "Party-2"

# 4. Party 3 contributes
mpc-ceremony contribute -i ceremony_p2.bin -o ceremony_final.bin --name "Party-3"

# 5. Verify ceremony
mpc-ceremony verify -i ceremony_final.bin --verbose

# 6. Export keys
mpc-ceremony export -i ceremony_final.bin -o ./keys --format rust
mpc-ceremony export -i ceremony_final.bin -o ./keys --format bin
```

### Integrating Keys

```bash
# Copy verifying key to on-chain program
cp keys/verifying_key.rs privacy-pool/src/circuit_vk.rs

# Copy proving key to WASM prover
cp keys/proving_key.bin privacy-pool-wasm/pkg/

# Rebuild and redeploy
cd privacy-pool && cargo build-sbf
```

## 💰 Privacy Pool Flow

### Deposit (Public)

1. User generates secret + nullifier locally
2. Computes commitment = `Poseidon(secret, Poseidon(nullifier, amount))`
3. Sends deposit transaction with commitment
4. Pool stores commitment in Merkle tree

### Withdraw (Private)

1. User generates ZK proof locally (in browser via WASM)
   - Proves: "I know secret/nullifier for a commitment in the tree"
   - Reveals: nullifier_hash, recipient, amount
   - Hides: secret, nullifier, which commitment
2. Relayer submits proof on-chain (user doesn't sign!)
3. Program verifies proof and transfers funds to recipient
4. Nullifier marked as used (prevents double-spend)

```
┌─────────────┐    commitment    ┌─────────────┐
│  Depositor  │ ───────────────► │    Pool     │
└─────────────┘                  │  (on-chain) │
                                 └──────┬──────┘
┌─────────────┐    ZK proof      ┌──────▼──────┐
│   Relayer   │ ◄─────────────── │  Recipient  │
└──────┬──────┘                  └─────────────┘
       │                                ▲
       │  submit proof                  │
       └────────────────────────────────┘
              funds transferred
```

## 🧪 Testing

### Unit Tests

```bash
# MPC ceremony simulation
cd privacy-pool && cargo test test_mpc_ceremony_simulation -- --nocapture

# Circuit constraint tests
cd privacy-pool && cargo test --test integration_test -- --nocapture
```

### On-Chain Tests (Devnet)

```bash
# Requires funded payer wallet (~0.5 SOL)
solana airdrop 1 --url devnet

# Run full privacy flow on devnet
cd privacy-pool && cargo test test_privacy_pool_onchain -- --nocapture
```

## 📊 Performance

| Metric | Value |
|--------|-------|
| Proof generation (browser) | ~0.1s |
| Proof size | 128 bytes |
| Verifying key size | ~965 bytes |
| On-chain verification | ~97K compute units |
| Circuit constraints | 77 |

## 🔒 Before Mainnet

- [ ] Run MPC ceremony with **real, independent participants**
- [ ] Professional **security audit**
- [ ] **Bug bounty program**
- [ ] Formal verification (optional)
- [ ] Multi-sig admin for pause functionality

## 📜 License

MIT OR Apache-2.0

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Run tests (`./scripts/test-privacy-pool.sh`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing`)
6. Open Pull Request

