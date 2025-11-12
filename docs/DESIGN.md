# Design Document: Solana BPF zkVM

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [BPF Tracing Strategy](#bpf-tracing-strategy)
3. [Circuit Design](#circuit-design)
4. [Proof Strategy](#proof-strategy)
5. [Security Model](#security-model)
6. [Future Optimizations](#future-optimizations)

## Architecture Overview

The Solana BPF zkVM consists of four main components that work together to prove correct execution of BPF programs using zero-knowledge proofs.

### System Architecture

```
┌─────────────┐
│ BPF Program │
│  (bytecode) │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  bpf-tracer     │  ← Wraps solana-sbpf VM
│                 │  ← Instruments execution
│  - VM wrapper   │  ← Captures complete trace
│  - Trace data   │
└────────┬────────┘
         │ ExecutionTrace
         ▼
┌─────────────────┐
│  zk-circuits    │  ← Halo2 circuit definitions
│                 │  ← BPF instruction chips
│  - Instruction  │  ← Counter circuit
│    chips        │
│  - Counter      │
│    circuit      │
└────────┬────────┘
         │ Circuit + Witness
         ▼
┌─────────────────┐
│  prover         │  ← Orchestration layer
│                 │  ← Witness generation
│  - Witness gen  │  ← Proof creation
│  - Proof gen    │  ← Verification
│  - Verification │
└────────┬────────┘
         │
         ▼
    ┌────────┐
    │ Proof  │ + Public Inputs
    └────────┘
```

### Component Responsibilities

#### bpf-tracer

**Purpose**: Capture complete execution traces of BPF programs.

**Key Features**:
- Wraps `solana-sbpf` VM with instrumentation hooks
- Records every instruction execution with before/after state
- Tracks all memory operations (reads and writes)
- Captures initial and final register states
- Provides serializable trace format

**API**:
```rust
pub fn trace_program(bytecode: &[u8]) -> Result<ExecutionTrace>
```

**Data Structures**:
- `ExecutionTrace`: Complete program execution record
- `InstructionTrace`: Single instruction with state transitions
- `MemoryOperation`: Memory read/write with address and value
- `RegisterState`: Snapshot of all 11 BPF registers (r0-r10)

#### zk-circuits

**Purpose**: Define ZK circuits for proving BPF instruction execution.

**Key Features**:
- Uses `halo2-lib` (Axiom fork) for circuit primitives
- Implements `BpfInstructionChip` trait for each instruction type
- Provides `CounterCircuit` for proving counter program execution
- Constrains instruction semantics and state transitions
- Supports public inputs for initial/final state commitments

**Instruction Chips**:
- `ALU64_ADD_IMM`: Add immediate to register
- `ALU64_ADD_REG`: Add register to register
- `STW`: Store 64-bit word to memory
- `LDW`: Load 64-bit word from memory
- `EXIT`: Program termination

**Circuit Structure**:
```rust
CounterCircuit {
    trace: ExecutionTrace,  // Private witness
    // Public inputs: initial_hash, final_hash
}
```

#### prover

**Purpose**: High-level API for proof generation and verification.

**Key Features**:
- Converts traces to circuit witnesses
- Manages Halo2 proving/verifying keys
- Generates succinct proofs
- Verifies proofs with public inputs
- Computes state commitments (SHA256 hashes)

**High-Level API**:
```rust
pub fn prove_execution(trace: ExecutionTrace)
    -> Result<(Proof, PublicInputs)>

pub fn verify_execution(proof: &Proof, public_inputs: &PublicInputs)
    -> Result<bool>
```

#### counter-program

**Purpose**: Minimal `no_std` BPF program for demonstration.

**Features**:
- Pure Rust, no Solana SDK dependencies
- Single function: increment 64-bit counter
- Compiles to `bpfel-unknown-unknown` target
- Uses only basic BPF instructions
- Suitable for end-to-end testing

**Program Logic**:
1. Read counter value from memory (pointer in r1)
2. Increment by 1 (with wrapping)
3. Write back to memory
4. Return success (0)

## BPF Tracing Strategy

### Why Tracing?

To prove BPF program execution in zero-knowledge, we need a complete record of what happened during execution. The trace provides the private witness for the ZK circuit.

### What Gets Traced

**Per Instruction**:
- Program counter (PC): Which instruction is executing
- Instruction bytes: Raw bytecode of the instruction
- Register state before: All 11 registers (r0-r10) before execution
- Register state after: All 11 registers after execution

**Memory Operations**:
- Address: Memory location being accessed
- Value: Data read or written
- Operation type: Read or Write

**Overall Execution**:
- Initial state: Registers at program start
- Final state: Registers at program exit
- Instruction sequence: Complete execution path

### Instrumentation Approach

The tracer wraps `solana-sbpf`'s VM and intercepts:

1. **Instruction Fetch**: Capture PC and instruction bytes
2. **Pre-Execution**: Snapshot all register values
3. **Execution**: Let VM execute the instruction
4. **Post-Execution**: Snapshot register values again
5. **Memory Access**: Intercept load/store operations
6. **Program Exit**: Capture final state

### Trace Format

The trace is serializable to JSON for debugging and stored efficiently for circuit witness generation:

```json
{
  "instructions": [
    {
      "pc": 0,
      "instruction_bytes": [0x18, 0x01, ...],
      "registers_before": {"regs": [0, 0, ...]},
      "registers_after": {"regs": [0, 42, ...]}
    },
    ...
  ],
  "memory_ops": [
    {
      "address": 0x1000,
      "value": 42,
      "op_type": "Read"
    },
    ...
  ],
  "initial_registers": {"regs": [0, 0, ...]},
  "final_registers": {"regs": [0, 0, ...]}
}
```

### Performance Considerations

**Trace Size**: For a simple counter program:
- ~10 instructions × 11 registers × 8 bytes = ~880 bytes register data
- ~2 memory operations × 16 bytes = ~32 bytes
- Total: ~1 KB trace

**Overhead**: Tracing adds instrumentation overhead, but since we're proving (not optimizing execution), this is acceptable.

## Circuit Design

### Overview

The ZK circuit proves that the execution trace satisfies all BPF instruction semantics. Each instruction in the trace corresponds to constraints in the circuit.

### Circuit Architecture

```
Input (Public):
  - initial_value_hash: SHA256(initial_registers)
  - final_value_hash: SHA256(final_registers)

Witness (Private):
  - ExecutionTrace: Complete program execution

Constraints:
  For each instruction i in trace:
    1. Verify instruction is valid BPF bytecode
    2. Verify register_after[i] = f(register_before[i], instruction[i])
    3. Verify memory consistency

  Verify: hash(initial_registers) == initial_value_hash
  Verify: hash(final_registers) == final_value_hash
```

### BPF Instruction Chips

Each instruction type implements `BpfInstructionChip`:

#### ALU64_ADD_IMM Chip

**Bytecode**: `0x07 | (dst << 4), 0x00, 0x00, 0x00, imm (4 bytes)`

**Constraints**:
```
registers_after[dst] = registers_before[dst] + imm (mod 2^64)
registers_after[j] = registers_before[j]  (for j != dst)
```

**Circuit Implementation**:
```rust
fn synthesize(&self) -> Result<()> {
    // Load registers from witness
    let before = load_registers();
    let after = load_registers();
    let imm = load_immediate();

    // Constrain: after[dst] = before[dst] + imm
    let sum = gate.add(before[dst], imm);
    gate.assert_equal(sum, after[dst]);

    // Constrain: other registers unchanged
    for i in 0..11 {
        if i != dst {
            gate.assert_equal(before[i], after[i]);
        }
    }

    Ok(())
}
```

#### Memory Load/Store Chips

**LDW (Load Word)**:
```
Constraints:
  - registers_after[dst] = memory[address]
  - address = registers_before[src] + offset
  - Other registers unchanged
```

**STW (Store Word)**:
```
Constraints:
  - memory[address] = registers_before[src]
  - address = registers_before[dst] + offset
  - Registers unchanged
```

**Memory Consistency**: Track memory operations to ensure loads read the most recent stored value.

### CounterCircuit

The counter circuit ties together instruction chips:

```rust
impl CounterCircuit {
    fn synthesize(&self) -> Result<()> {
        // 1. Hash initial state
        let initial_hash = sha256_chip.hash(&self.trace.initial_registers);
        gate.assert_equal(initial_hash, public_input[0]);

        // 2. Verify each instruction
        let mut current_regs = self.trace.initial_registers;
        for inst_trace in &self.trace.instructions {
            let chip = instruction_chip_for(inst_trace);
            chip.synthesize();
            // Update current state
            current_regs = inst_trace.registers_after;
        }

        // 3. Hash final state
        let final_hash = sha256_chip.hash(&current_regs);
        gate.assert_equal(final_hash, public_input[1]);

        // 4. Verify memory consistency
        verify_memory_ops(&self.trace.memory_ops);

        Ok(())
    }
}
```

### Circuit Complexity

**Target**: <100k constraints for demo

**Estimate** (per instruction):
- Register loading: ~50 constraints
- Arithmetic operation: ~100 constraints
- Register storing: ~50 constraints
- **Total per instruction**: ~200 constraints

**For 10 instruction counter**:
- Instructions: 10 × 200 = 2,000 constraints
- SHA256 hashes: 2 × 25,000 = 50,000 constraints
- **Total**: ~52,000 constraints ✓

### Halo2 Integration

**Using halo2-lib (Axiom fork)**:
- `FlexGateChip`: Basic arithmetic (add, mul, assert_equal)
- `RangeChip`: Range checks for 64-bit values
- `Poseidon/SHA256 chips`: Cryptographic hashing

**Key Features**:
- Lookup arguments for efficient range checks
- Custom gates for BPF-specific operations
- Aggregation for batching multiple proofs

## Proof Strategy

### What Are We Proving?

**Claim**: "I executed a BPF program that transitioned from initial state S₀ to final state S₁"

**Public Statement**:
- `H(S₀)`: Hash of initial state (registers)
- `H(S₁)`: Hash of final state (registers)

**Private Witness**:
- Complete execution trace
- BPF program bytecode

**Circuit Verifies**:
1. Initial state hashes to H(S₀)
2. Each instruction executed correctly per BPF semantics
3. Final state hashes to H(S₁)
4. Memory operations are consistent

### Witness Generation

Convert `ExecutionTrace` to circuit witness:

```rust
pub fn generate_witness(trace: &ExecutionTrace) -> Result<Witness> {
    let mut witness = Witness::new();

    // Add initial registers as witness
    for reg in trace.initial_registers.regs {
        witness.push(Field::from(reg));
    }

    // Add each instruction trace
    for inst in &trace.instructions {
        witness.push_instruction(inst);
    }

    // Add memory operations
    for mem_op in &trace.memory_ops {
        witness.push_memory_op(mem_op);
    }

    // Add final registers
    for reg in trace.final_registers.regs {
        witness.push(Field::from(reg));
    }

    Ok(witness)
}
```

### Proof Generation

```rust
pub fn create_proof(witness: Witness) -> Result<Proof> {
    // 1. Load or generate proving key
    let pk = load_or_generate_pk()?;

    // 2. Create circuit instance with witness
    let circuit = CounterCircuit::from_witness(witness);

    // 3. Generate proof using Halo2
    let proof = halo2::create_proof(
        &params,
        &pk,
        &[circuit],
        &[&public_inputs],
    )?;

    Ok(proof)
}
```

### Verification

```rust
pub fn verify_proof(proof: &Proof, public_inputs: &PublicInputs) -> Result<bool> {
    // 1. Load verifying key
    let vk = load_vk()?;

    // 2. Prepare public inputs
    let inputs = [
        public_inputs.initial_value_hash,
        public_inputs.final_value_hash,
    ];

    // 3. Verify proof using Halo2
    let valid = halo2::verify_proof(
        &params,
        &vk,
        &proof,
        &[&inputs],
    )?;

    Ok(valid)
}
```

### Proof Properties

**Succinctness**: Proof size is constant (~100-500 bytes) regardless of program length

**Verification Time**: ~10-50ms, much faster than re-execution

**Zero-Knowledge**: Proof reveals nothing about execution trace, only that it's valid

**Soundness**: Computationally infeasible to create fake proof for invalid execution

## Security Model

### Threat Model

**Assumptions**:
1. Halo2 proof system is secure (standard cryptographic assumptions)
2. BPF VM implementation (solana-sbpf) is correct
3. Circuit implementation correctly encodes BPF semantics
4. Cryptographic hash function (SHA256) is collision-resistant

**Trusted Setup**: Halo2 uses transparent setup (no trusted setup ceremony required)

### What Is Proven

✅ **Proven**:
- Every instruction in the trace executed correctly per BPF spec
- Register state transitions are valid
- Memory operations are consistent
- Program transitioned from claimed initial to final state

❌ **NOT Proven** (in current implementation):
- Program bytecode is specific counter program (any program accepted)
- Initial state came from legitimate source
- Final state will be used correctly
- No side effects outside the BPF VM (I/O, syscalls)

### Attack Vectors

**Circuit Implementation Bugs**: Most critical risk. If circuit doesn't correctly encode BPF semantics, proofs could be invalid.

*Mitigation*: Extensive testing, formal verification (future work)

**Soundness Bugs**: If circuit has logical errors, attacker could prove false statements.

*Mitigation*: Security audits, property-based testing

**VM Implementation Bugs**: If solana-sbpf doesn't match spec, traces could be incorrect.

*Mitigation*: Use well-tested VM, verify against official BPF validator

**Under-constrained Circuits**: Missing constraints allow invalid witnesses.

*Mitigation*: Completeness checks, constraint coverage analysis

### Current Limitations

⚠️ **This is a research prototype**:
- Incomplete BPF instruction set (only 5 instructions)
- No syscall support
- Simplified memory model
- No formal security audit
- **NOT production-ready**

### Future Security Enhancements

1. **Formal Verification**: Prove circuit correctness mathematically
2. **Constraint Coverage**: Ensure all BPF semantics are constrained
3. **Fuzz Testing**: Generate random programs and verify proofs
4. **Security Audit**: External review by cryptography experts
5. **Circuit Optimization**: Reduce attack surface through simpler circuits

## Future Optimizations

### Performance Improvements

**Current**: 10 instruction program → ~52k constraints → ~500ms proving time

**Optimization Targets**:

1. **Batching**: Prove multiple programs in single proof
   - Amortize setup costs
   - Better hardware utilization
   - Target: 10x throughput improvement

2. **Lookup Tables**: Use Halo2 lookups for common operations
   - Replace range checks with table lookups
   - Precompute common instruction patterns
   - Target: 3x constraint reduction

3. **Custom Gates**: Implement BPF-specific gates
   - Single gate for entire instruction
   - Reduce witness size
   - Target: 2x constraint reduction

4. **Recursive Proofs**: Prove subprograms separately, aggregate
   - Parallel proof generation
   - Incremental verification
   - Target: Enable unbounded program length

### Feature Additions

**Full BPF Instruction Set**:
- Branches and jumps (conditional execution)
- Function calls and returns
- Bitwise operations (AND, OR, XOR, shifts)
- Memory operations (8-bit, 16-bit, 32-bit)
- Comparison operations

**Syscall Support**:
- Syscall routing in circuit
- Merkle proofs for syscall correctness
- External state commitments

**Memory Optimizations**:
- Merkle tree memory representation
- Incremental memory proofs
- Sparse memory layout

**Cross-Program Invocation (CPI)**:
- Prove call graphs across programs
- Compositional verification
- Subproof aggregation

### Tooling and UX

**Developer Experience**:
- Debugging tools for circuit development
- Visualization of circuit structure
- Profiling for constraint optimization
- Error messages for invalid proofs

**Integration**:
- CLI tool for proof generation
- Web interface for verification
- SDK for embedding in applications
- Cloud prover for outsourced proving

**Testing Infrastructure**:
- Formal verification tools
- Fuzz testing framework
- Regression test suite
- Benchmark suite

### Research Directions

**Alternative Proof Systems**:
- Compare Halo2 vs. other SNARKs (Plonk, Groth16)
- Explore STARKs for better transparency
- Hybrid approaches

**Specialized Circuits**:
- Domain-specific optimizations (DeFi, NFTs)
- Custom instruction sets
- Hardware acceleration

**Scaling**:
- Proof aggregation schemes
- Distributed proving
- Incremental computation

---

## References

- [Halo2 Documentation](https://zcash.github.io/halo2/)
- [sBPF Specification](https://github.com/solana-labs/rbpf)
- [Axiom Halo2 Library](https://github.com/axiom-crypto/halo2-lib)
- [Solana BPF Programs](https://solana.com/docs/programs)

## Contributing

For design discussions and improvements, please open an issue or PR.
