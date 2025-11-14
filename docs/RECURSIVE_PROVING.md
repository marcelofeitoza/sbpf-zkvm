# Recursive Proving Architecture

## Overview

This document describes the two-tier recursive proving system that enables the zkVM to prove execution traces of arbitrary length.

## Problem

The original architecture generated proving keys with a fixed circuit size determined at keygen time. This meant:
- Keygen used an empty trace → fixed small circuit
- Prover with N instructions → circuit size N (different from keygen)
- Result: **Verification fails** due to circuit shape mismatch

## Solution: Two-Tier Recursion

### Tier 1: Chunked Proving
- Split execution trace into fixed-size chunks
- Each chunk contains up to `CHUNK_SIZE` instructions
- Prove each chunk independently (parallelizable)
- Last chunk padded if necessary

### Tier 2: Recursive Aggregation
- Aggregation circuit verifies all chunk proofs recursively
- Constrains state continuity between chunks
- Produces single final proof

## Chunk Parameters

### CHUNK_SIZE

**Definition**: Maximum number of instructions per chunk

**Considerations**:
1. **Constraint Count**: Each instruction adds ~50-200 constraints
   - Small chunks (100 instr) → ~5k-20k constraints → fast proving
   - Large chunks (10k instr) → ~500k-2M constraints → slower proving

2. **Proving Time**:
   - Linear in chunk size for tier 1
   - Recursive overhead dominates for many small chunks
   - Sweet spot: balance between chunk proving time and aggregation overhead

3. **Memory Usage**:
   - Proportional to chunk size (circuit witness size)
   - Larger chunks need more RAM during proving

4. **Parallelization**:
   - More chunks → more parallelization opportunity
   - Fewer chunks → less aggregation overhead

### Recommended Values

| Chunk Size | Use Case | Proving Time (est) | Memory | Parallelization |
|------------|----------|-------------------|---------|-----------------|
| 100        | Development/Testing | ~0.1s/chunk | Low | High |
| 1000       | **Recommended** | ~1s/chunk | Medium | Good |
| 5000       | Large programs | ~5s/chunk | High | Medium |
| 10000      | Maximum | ~10s/chunk | Very High | Low |

**Default**: `CHUNK_SIZE = 1000`

**Rationale**:
- 1000 instructions → ~50k-200k constraints per chunk
- Fast enough for responsive proving (~1s per chunk)
- Good parallelization (100k instruction trace → 100 chunks)
- Reasonable memory usage (~1-2GB per chunk)

### Circuit Parameters

**Per-Chunk Circuit (Tier 1)**:
```rust
pub struct ChunkCircuitParams {
    /// Circuit size parameter (2^k rows)
    pub k: u32,  // Default: 17 (131k rows)

    /// Lookup bits for range checks
    pub lookup_bits: usize,  // Default: 8

    /// Max instructions per chunk (fixed)
    pub chunk_size: usize,  // Default: 1000
}
```

**Aggregation Circuit (Tier 2)**:
```rust
pub struct AggregationCircuitParams {
    /// Circuit size for aggregation
    pub k: u32,  // Default: 20 (1M rows) - larger for recursion

    /// Max chunks to aggregate in one pass
    pub max_chunks: usize,  // Default: 1000
}
```

## Padding Strategy

### Why Padding?

Halo2 requires circuits to have fixed shape. If a chunk has fewer than `CHUNK_SIZE` instructions, we must pad it.

### Padding Approach

**Option 1: NOP Instructions** (Chosen)
- Pad with BPF NOP instructions (0x00 opcode)
- Circuit verifies NOPs do nothing (registers unchanged)
- Simple to implement and verify

**Option 2: Dummy Witnesses**
- Fill unused slots with dummy values
- Add boolean flag `is_real_instruction`
- Circuit checks: if !is_real, skip verification

**Option 3: Dynamic Sizing**
- Use different circuits for different chunk sizes
- Multiple keygens (k=10, k=12, k=15, etc.)
- Choose closest size for each chunk

**Chosen**: Option 1 (NOP padding) for simplicity

### Padding Implementation

```rust
fn pad_chunk(instructions: Vec<InstructionTrace>, chunk_size: usize) -> Vec<InstructionTrace> {
    let mut padded = instructions;

    while padded.len() < chunk_size {
        // Add NOP instruction (registers unchanged)
        let nop = InstructionTrace {
            pc: 0,
            instruction_bytes: vec![0x00; 8],  // NOP
            registers_before: padded.last().map(|i| i.registers_after).unwrap_or_default(),
            registers_after: padded.last().map(|i| i.registers_after).unwrap_or_default(),
        };
        padded.push(nop);
    }

    padded
}
```

## State Continuity

### Problem

Chunks must form a valid execution chain:
```
Chunk 0: regs[0..1000]   → initial_regs -> final_regs_0
Chunk 1: regs[1000..2000] → initial_regs_1 -> final_regs_1
...

Constraint: final_regs_0 == initial_regs_1
```

### Solution

**Public Inputs per Chunk**:
- `initial_registers`: RegisterState (11 u64 values = 88 bytes)
- `final_registers`: RegisterState (88 bytes)
- `chunk_index`: u32 (for ordering)

**Aggregation Circuit Constraints**:
```rust
for i in 0..num_chunks-1 {
    // Verify chunk proofs
    verify_proof(chunk_proofs[i], chunk_vk);

    // Extract public inputs
    let final_i = chunk_proofs[i].public_inputs.final_registers;
    let initial_next = chunk_proofs[i+1].public_inputs.initial_registers;

    // Constrain continuity
    constrain_equal(final_i, initial_next);
}
```

## Proving Flow

### Phase 1: Chunked Proving

```
Input: ExecutionTrace (N instructions)

1. chunk_size = config.chunk_size (e.g., 1000)
2. num_chunks = ceil(N / chunk_size)
3. For each chunk i in 0..num_chunks:
     a. Extract instructions[i*chunk_size .. (i+1)*chunk_size]
     b. Pad to chunk_size if needed
     c. Create ChunkCircuit with instructions
     d. Generate proof_i using chunk_pk
     e. Extract public_inputs_i (initial/final regs)
4. Return: (chunk_proofs[], chunk_public_inputs[])
```

### Phase 2: Recursive Aggregation

```
Input: (chunk_proofs[], chunk_public_inputs[])

1. Create AggregationCircuit:
     - Input: chunk_proofs[], chunk_vk
     - Constraints:
         * Verify each chunk proof
         * Check state continuity
         * Check chunk ordering
2. Synthesize aggregation circuit
3. Generate final_proof using aggregation_pk
4. Public inputs: (trace_initial_regs, trace_final_regs)
5. Return: (final_proof, final_public_inputs)
```

## Performance Analysis

### Proving Time

**Single Chunk (k=17, 1000 instructions)**:
- Circuit synthesis: ~0.1s
- Proof generation: ~0.5-1.0s
- **Total: ~1s per chunk**

**Aggregation (k=20, N chunks)**:
- Verifier circuit per chunk: ~10k constraints
- N chunks → ~N * 10k constraints
- For N=100: ~1M constraints → ~5-10s
- **Total: ~5-10s for aggregation**

**Full Trace (100k instructions)**:
- Tier 1: 100 chunks × 1s = 100s (parallelizable → ~10s with 10 cores)
- Tier 2: 100 chunks → ~7s
- **Total: ~17s (parallelized) or ~107s (sequential)**

### Memory Usage

**Per Chunk**:
- Witness size: ~1-2GB
- 10 parallel chunks → 10-20GB RAM

**Aggregation**:
- Verifier circuit witness: ~5-10GB
- **Total: ~15-30GB RAM (with parallelization)**

### Proof Size

**Chunk Proof**: ~400-600 bytes (SHPLONK + Blake2b)
**Aggregation Proof**: ~400-600 bytes
**Total**: ~500 bytes (constant, regardless of trace length!)

## Optimizations

### Future Work

1. **Lazy Aggregation**: Aggregate in batches (binary tree)
   - Instead of 100 chunks → 1 proof
   - 100 chunks → 10 intermediate → 1 final
   - Reduces aggregation circuit size

2. **Instruction-Specific Circuits**: Use different circuits per opcode
   - ALU operations: small circuit
   - Memory operations: larger circuit with lookups
   - Reduces per-chunk constraint count

3. **Parallel Aggregation**: Aggregate subsets in parallel
   - 100 chunks → 10 parallel aggregations → 1 final
   - Faster than sequential aggregation

4. **Compression**: Post-process final proof
   - Use EVM verifier (snark-verifier features)
   - ~200-300 byte final proof

## References

- Halo2 Book: https://zcash.github.io/halo2/
- Axiom snark-verifier: https://github.com/axiom-crypto/snark-verifier
- Recursive SNARKs: https://eprint.iacr.org/2019/1021.pdf
