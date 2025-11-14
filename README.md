# Solana BPF zkVM

A zero-knowledge virtual machine (zkVM) that proves Solana BPF program execution using Halo2. This is a minimal demonstration focused on proving a simple counter program written in pure `no_std` Rust without `solana-sdk` dependencies.

## Architecture Overview

```
BPF Bytecode → bpf-tracer → ExecutionTrace → zk-circuits → Proof
                                                              ↓
                                                         Verifier
```

The project consists of four main components:

1. **bpf-tracer**: Wraps the solana-sbpf VM to capture complete execution traces
2. **zk-circuits**: Implements Halo2 circuits for BPF instruction verification
3. **prover**: Orchestrates witness generation, proof creation, and verification
4. **counter-program**: Minimal `no_std` BPF program that increments a counter

## Project Structure

```
sbpf-zkvm/
├── bpf-tracer/           # Execution trace capture
│   ├── src/
│   │   ├── lib.rs        # Public API
│   │   ├── trace.rs      # Trace data structures
│   │   └── vm.rs         # VM wrapper with instrumentation
│   └── Cargo.toml
├── zk-circuits/          # ZK circuits for BPF instructions
│   ├── src/
│   │   ├── lib.rs        # Public API
│   │   ├── chips.rs      # BPF instruction chips
│   │   └── counter.rs    # Counter circuit implementation
│   └── Cargo.toml
├── prover/               # Proof generation orchestration
│   ├── src/
│   │   ├── lib.rs        # High-level API
│   │   ├── public_inputs.rs  # Public input handling
│   │   └── witness.rs    # Witness generation
│   ├── examples/
│   │   └── demo.rs       # End-to-end demo
│   └── Cargo.toml
├── examples/
│   └── counter-program/  # Minimal no_std BPF program
│       ├── src/
│       │   └── lib.rs    # Counter increment logic
│       └── Cargo.toml
├── deps/                 # Git submodules
│   ├── sbpf/            # Anza SBPF VM
│   └── halo2-lib/       # Axiom Halo2 library
├── docs/
│   └── DESIGN.md        # Detailed design documentation
├── Cargo.toml           # Workspace configuration
├── rust-toolchain.toml  # Rust toolchain specification
└── justfile             # Build automation
```

## Quick Start

### Prerequisites

- Rust stable toolchain (automatically configured via `rust-toolchain.toml`)
- Git with submodule support
- [just](https://github.com/casey/just) command runner (optional but recommended)

### Setup

```bash
# Clone the repository
git clone <repository-url>
cd sbpf-zkvm

# Initialize git submodules
git submodule update --init --recursive

# Or use just for automated setup
just setup
```

### Build

```bash
# Initialize git submodules (required first time)
git submodule update --init --recursive
# Or use just
just init

# Build all workspace crates
cargo build --workspace

# Or use just
just build

# Build the BPF counter program (uses Solana toolchain via rust-toolchain.toml)
just build-bpf
```

### Run the Demo

```bash
# Run the end-to-end demonstration
cargo run --example demo

# Or use just
just demo

# Run with verbose logging
RUST_LOG=debug cargo run --example demo
# Or
just demo-verbose
```

### Run Tests

```bash
# Run all tests
cargo test --workspace

# Or use just
just test
```

## What Gets Proven

The zkVM proves that a BPF counter program executed correctly by:

1. **Loading** a BPF program bytecode
2. **Tracing** its execution to capture:
   - Every instruction executed (with before/after register states)
   - All memory operations (reads and writes)
   - Initial and final program state
3. **Generating** a ZK circuit that constrains:
   - Each instruction executed according to BPF semantics
   - Register transitions are correct
   - Memory consistency is maintained
4. **Creating** a succinct proof that can be verified without re-executing
5. **Verifying** the proof with only public inputs (state commitments)

## Minimal BPF Instruction Set

The demo implements circuits for the minimal instruction subset needed for the counter:

- `ALU64_ADD_IMM` - Add immediate value to 64-bit register
- `ALU64_ADD_REG` - Add register to register
- `STW` - Store 64-bit word to memory
- `LDW` - Load 64-bit word from memory
- `EXIT` - Program exit

## Counter Program

The example counter program is written in pure `no_std` Rust without any Solana SDK dependencies:

```rust
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    let counter_ptr = input as *mut u64;
    let current_value = core::ptr::read_volatile(counter_ptr);
    let new_value = current_value.wrapping_add(1);
    core::ptr::write_volatile(counter_ptr, new_value);
    0  // Success
}
```

This compiles to BPF bytecode that can be proven by the zkVM.

## Development

### Available Commands (via just)

```bash
just init            # Initialize git submodules
just setup           # Full development environment setup
just build           # Build all crates
just build-bpf       # Build counter program to BPF
just test            # Run all tests
just demo            # Run end-to-end demo
just clippy          # Run linter
just fmt             # Format code
just check           # Full check (format + clippy + test + build)
just clean           # Clean build artifacts
just stats           # Show project statistics
```

### Building Individual Crates

```bash
# Build specific crates
cargo build -p bpf-tracer
cargo build -p zk-circuits
cargo build -p prover

# Build counter-program (must be done from its directory due to Solana toolchain)
cd examples/counter-program && cargo build --target sbf-solana-solana --release
# Or use just from root
just build-bpf
```

### Testing

```bash
# Test all crates
cargo test --workspace

# Test specific crate
cargo test -p bpf-tracer

# Test with output
cargo test --workspace -- --nocapture
```

## Implementation Status

### ✅ Completed

- [x] Project structure and workspace setup
- [x] Git submodules (sbpf, halo2-lib)
- [x] Trace data structures
- [x] Counter program (no_std BPF)
- [x] BPF build toolchain (Solana toolchain with sbf-solana-solana target)
- [x] Counter program BPF binary (1408 bytes)
- [x] Integration tests for counter program
- [x] High-level prover API
- [x] End-to-end demo skeleton
- [x] Build automation (justfile with working build-bpf recipe)

### 🚧 In Progress (Stub Implementations)

- [ ] BPF VM execution tracing (currently returns empty trace)
- [ ] Halo2 circuit implementation (stub)
- [ ] Witness generation (placeholder)
- [ ] Proof generation (dummy proof)
- [ ] Proof verification (accepts all)

### 📋 Future Work

- [ ] Complete BPF instruction set support
- [ ] Optimized circuits
- [ ] Merkle tree memory commitments
- [ ] Cross-program invocation (CPI)
- [ ] Syscall support
- [ ] Benchmarking infrastructure
- [ ] Fuzzing and property tests

## Performance Features

### Parallel Proving

The zkVM supports parallel proof generation for improved performance on multi-core systems:

```rust
use prover::{prove_execution_chunked_parallel, KeygenConfig};

// Prove chunks in parallel (4-8× faster on typical systems)
let chunk_proofs = prove_execution_chunked_parallel(trace, &config)?;
```

**Features**:
- Automatic multi-core utilization via Rayon
- Near-linear speedup with CPU cores (4-8× typical)
- Thread-safe key sharing (no extra copies)
- Control parallelism via `RAYON_NUM_THREADS` env var

**When to use**:
- **Parallel**: Large traces (>10 chunks), multi-core CPU, memory available
- **Sequential**: Small traces (<5 chunks), memory constrained systems

For details, see [docs/PARALLEL_PROVING.md](docs/PARALLEL_PROVING.md).

## Documentation

- [DESIGN.md](docs/DESIGN.md) - Detailed architecture and design decisions
- [RECURSIVE_PROVING.md](docs/RECURSIVE_PROVING.md) - Chunking architecture
- [PARALLEL_PROVING.md](docs/PARALLEL_PROVING.md) - Parallel proving guide
- [PHASE1_COMPLETE.md](docs/PHASE1_COMPLETE.md) - Phase 1 completion summary
- [PHASE2_ROADMAP.md](docs/PHASE2_ROADMAP.md) - Future aggregation plans
- [API Documentation](https://docs.rs) - Run `cargo doc --open` to view

## Dependencies

### Git Submodules

- [anza-xyz/sbpf](https://github.com/anza-xyz/sbpf) - Actively maintained Solana BPF VM
- [axiom-crypto/halo2-lib](https://github.com/axiom-crypto/halo2-lib) - Optimized Halo2 circuits library

### Key Crates

- `solana-sbpf` - BPF VM for execution
- `halo2-lib` - ZK circuit library
- `serde/serde_json` - Serialization
- `thiserror/anyhow` - Error handling
- `sha2` - Cryptographic hashing
- `tracing` - Structured logging

## Security Model

⚠️ **This is a research prototype for demonstration purposes only.**

Current limitations:
- Incomplete BPF instruction set coverage
- Placeholder cryptographic operations
- No formal security audits
- Not suitable for production use

For a detailed security analysis, see [docs/DESIGN.md](docs/DESIGN.md).

## Contributing

This is a demonstration project. For questions or suggestions, please open an issue.

## License

MIT OR Apache-2.0

## References

- [Solana BPF Documentation](https://solana.com/docs/programs/lang-rust)
- [Halo2 Book](https://zcash.github.io/halo2/)
- [sBPF Specification](https://github.com/solana-labs/rbpf/blob/main/doc/instruction_set.md)
