# WASM zkVM Prover

Browser-based zero-knowledge prover for Solana BPF programs. Generates Halo2 proofs entirely client-side.

## ⚠️ What This Proof Guarantees (and Does NOT)

### ✅ This proof DOES verify:

- **Execution trace consistency**: The sequence of instructions forms a valid trace
- **Register state transitions**: Register values flow correctly from step to step
- **Logging syscall returns**: `sol_log_` variants return 0 (success)
- **Register preservation**: Callee-saved registers (r6-r9) preserved across syscalls

### ❌ This proof does NOT verify:

- **Instruction semantics**: We don't prove that ADD actually adds, etc.
- **Memory correctness**: Memory read/write consistency is NOT proven
- **Account state changes**: Counter value changes are NOT committed or proven
- **Program bytecode**: We don't prove the program is authentic
- **Memory syscall effects**: `sol_memcpy_` etc. effects are NOT verified

**This is a proof-of-concept for privacy-preserving trace verification, NOT a production state proof.**

## Quick Start

### 1. Generate a trace file

```bash
# From the repo root:
cargo run -p trace-exporter -- --out counter.trace --initial 42
```

This will:
- Execute the counter program in the real Solana SBPF VM
- Capture the execution trace
- Validate all syscalls are whitelisted
- Export to binary format

### 2. Build WASM

```bash
cd wasm-prover
wasm-pack build --target web --release
```

### 3. Run in browser

```bash
cd www
ln -sf ../pkg pkg
python3 -m http.server 8080
# Open http://localhost:8080
```

### 4. Load trace and generate proof

1. Drag & drop `counter.trace` into the browser
2. Verify all syscalls show as "whitelisted"
3. Click "Generate Proof"
4. Click "Verify Proof"

## Syscall Support

### Fully Verified (logging - no side effects)
- `sol_log_` (0x56ffab99)
- `sol_log_64_` (0x5fdcde31)
- `sol_log_pubkey_`
- `sol_log_compute_units_`

### Allowed but Memory Effects NOT Verified
- `sol_memcpy_` (0x717cc4a3)
- `sol_memset_` (0xa20adc3a)
- `sol_memmove_` (0xbbb11f89)
- `sol_memcmp_` (0xce18c592)

### Not Allowed
- `abort`
- Unknown syscalls (unless `--allow-unknown-syscalls` flag)

## Trace Format

Binary format `SBPFZK02` (v2 with syscall support):

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 8 | Magic bytes `SBPFZK02` |
| 8 | 4 | Version (2) |
| 12 | 96 | Initial registers (12 × u64) |
| 108 | 96 | Final registers (12 × u64) |
| 204 | 4 | Step count |
| 208+ | variable | Steps (instructions and syscalls) |

Each instruction step:
- Type byte (0 = instruction)
- PC (8 bytes)
- Instruction bytes (8 bytes)
- Registers before (96 bytes)
- Registers after (96 bytes)

Each syscall step:
- Type byte (1 = syscall)
- PC (8 bytes)
- Syscall ID (4 bytes)
- Raw hash (4 bytes)
- Return value (8 bytes)
- Registers before (96 bytes)
- Registers after (96 bytes)

## Debug Mode

To export traces with unknown syscalls (NOT for production):

```bash
cargo run -p trace-exporter -- --out debug.trace --allow-unknown-syscalls
```

Traces exported this way will fail validation in the browser prover.

## Security Model

```
┌─────────────────────────────────────────────────────┐
│                    Browser                           │
│  ┌─────────────────────────────────────────────────┐│
│  │            WASM Memory (Private)                ││
│  │  • Execution Trace (from local file)            ││
│  │  • Circuit Witness                              ││
│  │  • Intermediate Values                          ││
│  └─────────────────────────────────────────────────┘│
│                         │                            │
│                         ▼                            │
│              ┌─────────────────┐                     │
│              │  Proof (Public) │ ──────────────────► │
│              └─────────────────┘    Only this        │
│                                     crosses the      │
│                                     WASM boundary    │
└─────────────────────────────────────────────────────┘
```

Private trace data (including log contents, register values, execution flow) never leaves the browser.

## API

```typescript
// Prove from trace bytes
prove_trace(trace_bytes: Uint8Array): Uint8Array

// Verify proof against trace
verify_trace_proof(proof: Uint8Array, trace_bytes: Uint8Array): boolean

// Get trace info (including syscall summary)
get_trace_info(trace_bytes: Uint8Array): string // JSON

// Get prover capabilities
get_prover_info(): string // JSON
```

## License

MIT OR Apache-2.0
