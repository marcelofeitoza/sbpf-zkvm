# Phase 2 Roadmap: Recursive Aggregation

## Current Status (End of Phase 1)

✅ **Chunking Architecture Complete**
- Traces split into fixed-size chunks
- Each chunk proved independently
- State continuity verified between chunks
- Returns `Vec<ChunkProof>` (multiple proofs)

## Phase 2 Goal

**Objective**: Aggregate multiple chunk proofs into a single final proof

**Outcome**: `prove_execution_chunked` returns a single proof regardless of trace length

---

## Architecture Overview

### Two-Tier Proving System

```
┌─────────────────────────────────────────────────────────────┐
│                        INPUT TRACE                           │
│                    (N instructions)                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 TIER 1: CHUNKED PROVING                      │
│                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Chunk 0  │  │ Chunk 1  │  │ Chunk 2  │  │ Chunk N  │   │
│  │(1k inst) │  │(1k inst) │  │(1k inst) │  │(1k inst) │   │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘   │
│        │             │             │             │          │
│        ▼             ▼             ▼             ▼          │
│   ┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐       │
│   │ Proof₀ │   │ Proof₁ │   │ Proof₂ │   │ ProofN │       │
│   └────────┘   └────────┘   └────────┘   └────────┘       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              TIER 2: RECURSIVE AGGREGATION                   │
│                                                               │
│              ┌────────────────────────┐                      │
│              │  Aggregation Circuit   │                      │
│              │                        │                      │
│              │  ┌──────────────────┐ │                      │
│              │  │ Verifier Circuit │ │  ← Verify Proof₀    │
│              │  └──────────────────┘ │                      │
│              │  ┌──────────────────┐ │                      │
│              │  │ Verifier Circuit │ │  ← Verify Proof₁    │
│              │  └──────────────────┘ │                      │
│              │  ┌──────────────────┐ │                      │
│              │  │ Verifier Circuit │ │  ← Verify Proof₂    │
│              │  └──────────────────┘ │                      │
│              │          ...           │                      │
│              │  ┌──────────────────┐ │                      │
│              │  │State Continuity  │ │  ← Constrain regs   │
│              │  └──────────────────┘ │                      │
│              └────────────────────────┘                      │
│                          │                                   │
│                          ▼                                   │
│                  ┌───────────────┐                           │
│                  │  Final Proof  │                           │
│                  │ (constant size)│                          │
│                  └───────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Implementation Steps

### Step 1: Add snark-verifier-sdk Dependency

```toml
[workspace.dependencies]
snark-verifier = { git = "...", tag = "v0.1.7", ... }
snark-verifier-sdk = { git = "...", tag = "v0.1.7", ... }
```

**Purpose**: SDK provides higher-level APIs for aggregation

### Step 2: Understand snark-verifier API

**Key Concepts**:
1. **PlonkProtocol**: Circuit description (constraint system)
2. **Snark**: Struct containing (protocol, instances, proof)
3. **Loader**: Abstraction for circuit vs native verification
4. **Accumulator**: For KZG accumulation scheme

**Files to Study**:
- `/snark-verifier/examples/recursion.rs` - Full recursion example
- `/snark-verifier-sdk/examples/standard_plonk.rs` - Simpler example
- `/snark-verifier-sdk/src/halo2.rs` - Halo2-specific helpers

### Step 3: Create Verifier Circuit

```rust
// pseudo-code
pub struct ChunkVerifierCircuit {
    /// The chunk proof to verify
    proof: Vec<u8>,

    /// Public inputs (initial/final registers)
    instances: Vec<Fr>,

    /// Circuit protocol (from keygen)
    protocol: PlonkProtocol<G1Affine>,
}

impl Circuit<Fr> for ChunkVerifierCircuit {
    fn synthesize(...) {
        // Use snark-verifier to verify chunk proof in-circuit
        let loader = Halo2Loader::new(...);
        let verifier = PlonkVerifier::new(...);

        // Load proof and verify
        let proof = PlonkProof::read(...);
        verifier.verify(&proof, &instances, &loader)?;

        // Extract public inputs for state continuity
        // ...
    }
}
```

**Challenges**:
- Circuit size: Verifier circuit is large (~10k-20k constraints)
- KZG accumulator: Need to handle accumulation correctly
- Transcript: Must match chunk proof generation transcript

### Step 4: Create Aggregation Circuit

```rust
pub struct AggregationCircuit {
    /// All chunk proofs to aggregate
    chunk_proofs: Vec<ChunkProof>,

    /// Chunk verifying key
    chunk_vk: VerifyingKey<G1Affine>,

    /// Max number of chunks
    max_chunks: usize,
}

impl Circuit<Fr> for AggregationCircuit {
    fn synthesize(...) {
        let loader = Halo2Loader::new(...);

        // For each chunk proof
        for (i, chunk_proof) in chunk_proofs.iter().enumerate() {
            // Verify chunk proof in-circuit
            verify_chunk_proof(chunk_proof, chunk_vk, loader)?;

            // Extract public inputs
            let initial_regs = extract_initial_registers(chunk_proof);
            let final_regs = extract_final_registers(chunk_proof);

            // Constrain state continuity
            if i > 0 {
                let prev_final = chunk_proofs[i-1].final_registers;
                constrain_equal(prev_final, initial_regs)?;
            }
        }

        // Public outputs: trace initial/final state
        self.expose_public(
            chunk_proofs[0].initial_registers,
            chunk_proofs.last().final_registers
        );
    }
}
```

**Challenges**:
- Variable number of chunks: Need to pad to max_chunks
- Public input handling: Extract and expose correctly
- Circuit size: N chunks → N verifier circuits (~N * 10k constraints)

### Step 5: Aggregation Keygen

```rust
pub fn generate_aggregation_keys(
    chunk_config: &KeygenConfig,
    max_chunks: usize,
) -> Result<AggregationKeyPair> {
    // Determine aggregation circuit size
    let agg_k = calculate_aggregation_k(max_chunks);

    // Create dummy aggregation circuit
    let dummy_chunks = vec![create_dummy_chunk_proof(); max_chunks];
    let agg_circuit = AggregationCircuit {
        chunk_proofs: dummy_chunks,
        chunk_vk: chunk_vk.clone(),
        max_chunks,
    };

    // Generate keys
    let params = ParamsKZG::setup(agg_k, OsRng);
    let vk = keygen_vk(&params, &agg_circuit)?;
    let pk = keygen_pk(&params, vk, &agg_circuit)?;

    Ok(AggregationKeyPair { params, pk, vk })
}
```

### Step 6: Update prove_execution_chunked

```rust
pub fn prove_execution_chunked(
    trace: ExecutionTrace,
    config: &KeygenConfig,
) -> Result<(Proof, PublicInputs)> {
    // Step 1: Split and prove chunks
    let chunks = split_trace_into_chunks(trace, config.chunk_size)?;
    let chunk_keypair = KeyPair::load_or_generate(config)?;

    let mut chunk_proofs = Vec::new();
    for chunk in chunks {
        let proof = create_proof(chunk, &chunk_keypair.pk, ...)?;
        chunk_proofs.push(proof);
    }

    // Step 2: Aggregate chunk proofs
    let agg_keypair = AggregationKeyPair::load_or_generate(config, max_chunks)?;

    let agg_circuit = AggregationCircuit {
        chunk_proofs,
        chunk_vk: chunk_keypair.vk,
        max_chunks: config.max_chunks,
    };

    let final_proof = create_aggregation_proof(
        agg_circuit,
        &agg_keypair.pk,
        &agg_keypair.params,
    )?;

    let public_inputs = PublicInputs {
        initial_registers: chunk_proofs[0].initial_registers,
        final_registers: chunk_proofs.last().final_registers,
    };

    Ok((final_proof, public_inputs))
}
```

---

## Technical Challenges

### 1. Circuit Size

**Problem**: Verifier circuit is large (~10k-20k constraints)

**Impact**:
- Aggregating 100 chunks → ~1-2M constraints
- Requires k=20 or k=21 (1M-2M rows)
- Slower proving time (~10-30s)

**Mitigation**:
- Use smaller k for chunks (k=15 or k=16)
- Optimize verifier circuit size
- Consider batched aggregation (binary tree)

### 2. Public Input Handling

**Problem**: Need to expose and constrain register states

**Current**: RegisterState is 11 × u64 = 88 bytes
**As Field Elements**: 11 Fr elements (can't fit full u64 in single Fr for BN254)

**Solution**:
- Decompose each u64 into limbs (e.g., 3 × 88-bit limbs)
- Total: 11 × 3 = 33 field elements per state
- Initial + Final = 66 field elements public input

### 3. Accumulator Management

**Problem**: KZG accumulator needs to be passed through

**snark-verifier Pattern**:
- Each verification produces an accumulator
- Accumulators must be combined
- Final accumulator verified natively

**Implementation**:
```rust
let mut accumulator = KzgAccumulator::default();
for chunk_proof in chunk_proofs {
    let new_acc = verify_and_accumulate(chunk_proof, accumulator)?;
    accumulator = new_acc;
}
// Final accumulator becomes part of public input
```

### 4. Transcript Coordination

**Problem**: Transcript must be consistent

**Challenge**: Blake2b (used in chunks) vs Poseidon (typical for recursion)

**Solution Options**:
1. **Change chunk transcript to Poseidon**: More efficient in-circuit
2. **Keep Blake2b**: More complex verifier circuit
3. **Hybrid**: Blake2b for chunks, convert to Poseidon for aggregation

**Recommendation**: Option 1 - Use Poseidon throughout

---

## Performance Estimates

### Single Chunk Verification (in-circuit)

- Circuit size: ~10k-20k constraints
- Verification time: ~50-100ms per chunk

### Aggregation (100 chunks)

- **Tier 1** (Chunk proving):
  - 100 chunks × 1s = 100s sequential
  - With 10 cores: ~10s parallel

- **Tier 2** (Aggregation):
  - Circuit: ~1-2M constraints
  - Proving time: ~10-30s

- **Total**: ~20-40s (parallelized)

### Proof Size

- Chunk proof: ~400-600 bytes
- Aggregated proof: ~400-600 bytes (constant!)
- **Space savings**: 100 × 500 bytes = 50KB → 500 bytes

---

## Alternative: Batched Aggregation

### Binary Tree Approach

Instead of aggregating all N chunks at once, aggregate in batches:

```
Level 0:  [C₀] [C₁] [C₂] [C₃] [C₄] [C₅] [C₆] [C₇]  (chunk proofs)
           ↓↓   ↓↓   ↓↓   ↓↓   ↓↓   ↓↓   ↓↓   ↓↓
Level 1:  [A₀₁]   [A₂₃]   [A₄₅]   [A₆₇]           (aggregate pairs)
            ↓↓     ↓↓       ↓↓     ↓↓
Level 2:   [A₀₁₂₃]        [A₄₅₆₇]                 (aggregate pairs)
              ↓↓             ↓↓
Level 3:      [Final]                              (final aggregation)
```

**Advantages**:
- Smaller circuits per level (only 2-4 proofs)
- Parallelizable at each level
- More flexible (can stop at any level)

**Disadvantages**:
- More proof generation steps
- More complex implementation

---

## Testing Strategy

### Unit Tests

1. **Test verifier circuit alone**:
   ```rust
   test_verify_single_chunk_proof()
   ```

2. **Test aggregation with 2 chunks**:
   ```rust
   test_aggregate_two_chunks()
   ```

3. **Test state continuity constraints**:
   ```rust
   test_state_continuity_enforced()
   ```

### Integration Tests

1. **Small trace (3 chunks)**:
   ```rust
   test_aggregate_small_trace()
   ```

2. **Medium trace (10 chunks)**:
   ```rust
   test_aggregate_medium_trace()
   ```

3. **Large trace (100 chunks)**:
   ```rust
   test_aggregate_large_trace()
   ```

### Verification Tests

1. **Verify aggregated proof**:
   ```rust
   test_aggregated_proof_verifies()
   ```

2. **Reject invalid state transition**:
   ```rust
   test_reject_broken_continuity()
   ```

---

## Dependencies

### Additional Crates Needed

```toml
[workspace.dependencies]
# Already have
snark-verifier = { ... }

# Need to add
snark-verifier-sdk = { git = "...", tag = "v0.1.7" }
poseidon-circuit = "..."  # For Poseidon hash in-circuit
```

### Feature Flags

Consider adding feature flags for flexibility:

```toml
[features]
default = ["aggregation"]
aggregation = ["snark-verifier", "snark-verifier-sdk"]
simple = []  # No aggregation, just chunked proofs
```

---

## Migration Path

### Phase 2A: Basic Aggregation (2 chunks)
- Week 3: Implement verifier circuit for single chunk
- Test: Aggregate 2 chunks into 1 proof

### Phase 2B: Multi-Chunk Aggregation
- Week 4: Generalize to N chunks
- Test: 10, 100, 1000 chunks

### Phase 2C: Optimization
- Week 5: Batched aggregation (binary tree)
- Performance tuning

---

## Success Criteria

✅ **Phase 2A Complete**:
- [ ] Verifier circuit implemented
- [ ] Can aggregate 2 chunk proofs
- [ ] Aggregated proof verifies
- [ ] State continuity enforced

✅ **Phase 2B Complete**:
- [ ] Can aggregate N chunks (up to max_chunks)
- [ ] End-to-end test: 1000 instruction trace → single proof
- [ ] Proof size constant (~500 bytes)

✅ **Phase 2C Complete**:
- [ ] Batched aggregation implemented
- [ ] Performance benchmarked
- [ ] Documentation complete

---

## References

- **snark-verifier repo**: https://github.com/axiom-crypto/snark-verifier
- **Recursion example**: `/snark-verifier/examples/recursion.rs`
- **Halo2 book**: https://zcash.github.io/halo2/
- **Axiom docs**: https://docs.axiom.xyz/

---

## Current Blockers

1. **Learning curve**: snark-verifier API is complex
2. **Documentation**: Limited examples and docs
3. **Debugging**: Circuit failures are hard to debug

## Recommendations

1. **Start simple**: Aggregate 2 chunks first
2. **Study examples**: Spend time understanding recursion.rs
3. **Ask community**: Axiom Discord for help
4. **Iterate**: Build incrementally, test frequently

---

**Status**: Phase 2 roadmap documented. Ready to begin implementation when needed.

**Estimated Effort**: 3-4 weeks for full implementation
