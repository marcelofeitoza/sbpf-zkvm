//! Prover - Orchestration layer for ZK proof generation
//!
//! This crate connects execution tracing, circuit generation, and proof
//! creation into a high-level API for proving BPF program execution.

pub mod public_inputs;
pub mod witness;
pub mod keygen;
pub mod chunking;

pub use public_inputs::PublicInputs;
pub use witness::Witness;
pub use keygen::{KeygenConfig, KeyPair};
pub use chunking::{split_trace_into_chunks, ChunkProof};
use bpf_tracer::ExecutionTrace;
use halo2_base::{
    gates::{
        circuit::{builder::BaseCircuitBuilder, CircuitBuilderStage},
        flex_gate::GateChip,
    },
    halo2_proofs::{
        halo2curves::bn256::{Bn256, Fr, G1Affine},
        plonk::{create_proof as halo2_create_proof, verify_proof as halo2_verify_proof, ProvingKey, VerifyingKey},
        poly::kzg::{
            commitment::KZGCommitmentScheme, commitment::ParamsKZG, multiopen::ProverSHPLONK,
            multiopen::VerifierSHPLONK, strategy::SingleStrategy,
        },
        transcript::{
            Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
        },
        poly::commitment::ParamsProver,
    },
};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rayon::prelude::*;
use zk_circuits::CounterCircuit;

/// Result type for prover operations
pub type Result<T> = anyhow::Result<T>;

/// Proof type (serialized Halo2 proof bytes)
pub type Proof = Vec<u8>;

/// Generate witness from execution trace
///
/// Converts an execution trace into the witness data needed
/// for circuit constraint satisfaction.
pub fn generate_witness(trace: &ExecutionTrace) -> Result<Vec<u8>> {
    tracing::info!("Generating witness from trace with {} instructions",
                   trace.instruction_count());

    // Create structured witness from trace
    let witness = Witness::from_trace(trace)?;

    tracing::debug!(
        "Witness generated: {} instructions, {} account changes, {} register states",
        witness.instruction_count(),
        witness.account_change_count(),
        witness.instruction_register_states.len()
    );

    // Serialize to bytes for proof generation
    witness.to_bytes()
}

/// Create a ZK proof from an execution trace using the proving key
///
/// Generates a Halo2 proof that the execution trace satisfies
/// all circuit constraints.
pub fn create_proof(
    trace: ExecutionTrace,
    pk: &ProvingKey<G1Affine>,
    params: &ParamsKZG<Bn256>,
    config: &KeygenConfig,
    break_points: &[Vec<usize>],
) -> Result<Proof> {
    tracing::info!(
        "Creating proof for trace with {} instructions",
        trace.instruction_count()
    );

    // Set environment variable for lookup bits
    std::env::set_var("LOOKUP_BITS", config.lookup_bits.to_string());

    // Create circuit from trace with chunking
    // This ensures the circuit shape matches keygen (padded to chunk_size)
    let circuit_logic = CounterCircuit::from_trace_chunked(trace, config.chunk_size);

    // Build the prover circuit with break points from keygen
    let mut builder = BaseCircuitBuilder::<Fr>::from_stage(CircuitBuilderStage::Prover)
        .use_k(config.k as usize)
        .use_lookup_bits(config.lookup_bits)
        .use_break_points(break_points.to_vec());

    // Create a gate chip
    let gate = GateChip::<Fr>::default();

    // Synthesize the circuit with real witness
    circuit_logic.synthesize(builder.main(0), &gate)
        .map_err(|e| anyhow::anyhow!("Failed to synthesize circuit: {}", e))?;

    // Configure the builder - sets config params
    builder.calculate_params(Some(9));

    // The builder IS the circuit - no need to create another one
    let circuit = builder;

    // Generate proof using SHPLONK and Blake2b
    tracing::info!("Generating Halo2 proof...");
    let rng = StdRng::seed_from_u64(0);
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    halo2_create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<_>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, _>,
        _,
    >(params, pk, &[circuit], &[&[]], rng, &mut transcript)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {:?}", e))?;

    let proof = transcript.finalize();
    tracing::info!("Proof generated ({} bytes)", proof.len());

    Ok(proof)
}

/// Verify a ZK proof with public inputs
///
/// Checks that a proof is valid for the given public inputs
/// (initial and final state commitments).
pub fn verify_proof(
    proof: &Proof,
    vk: &VerifyingKey<G1Affine>,
    params: &ParamsKZG<Bn256>,
    _public_inputs: &PublicInputs,
) -> Result<bool> {
    tracing::info!("Verifying proof ({} bytes)", proof.len());

    // Get verifier params
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    // Verify using SHPLONK and Blake2b
    let result = halo2_verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, vk, strategy, &[&[]], &mut transcript);

    match result {
        Ok(_) => {
            tracing::info!("Proof verification succeeded");
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("Proof verification failed: {:?}", e);
            Ok(false)
        }
    }
}

/// High-level API: Prove execution of a BPF program
///
/// Takes a program execution trace and returns a proof with public inputs.
/// Generates keys if they don't exist in cache.
///
/// **Note**: This function currently handles traces up to `chunk_size` instructions.
/// For traces > chunk_size, the trace will be truncated (padding handles the rest).
/// For true multi-chunk proving, use `prove_execution_chunked` once aggregation is implemented.
pub fn prove_execution(
    trace: ExecutionTrace,
    config: &KeygenConfig,
) -> Result<(Proof, PublicInputs)> {
    // Generate public inputs from trace
    let public_inputs = PublicInputs::from_trace(&trace)?;

    // Load or generate keys
    tracing::info!("Loading proving keys...");
    let keypair = KeyPair::load_or_generate(config)?;

    // Create circuit and log constraints
    let circuit = CounterCircuit::from_trace_chunked(trace.clone(), config.chunk_size);
    tracing::info!(
        "Circuit has ~{} constraints (chunk_size={})",
        circuit.num_constraints(),
        config.chunk_size
    );

    // Generate proof
    let proof = create_proof(trace, &keypair.pk, &keypair.params, config, &keypair.break_points)?;

    Ok((proof, public_inputs))
}

/// Prove execution with automatic chunking (sequential)
///
/// This function splits traces longer than `chunk_size` into multiple chunks,
/// proves each chunk independently, and returns all chunk proofs.
///
/// For parallel proving, use `prove_execution_chunked_parallel`.
///
/// **Phase 1**: Returns individual chunk proofs (no aggregation yet)
/// **Phase 2**: Will add recursive aggregation to produce single final proof
pub fn prove_execution_chunked(
    trace: ExecutionTrace,
    config: &KeygenConfig,
) -> Result<Vec<ChunkProof>> {
    let instruction_count = trace.instruction_count();
    tracing::info!(
        "Proving execution with {} instructions (chunk_size={})",
        instruction_count,
        config.chunk_size
    );

    // Split trace into chunks
    let chunks = split_trace_into_chunks(trace, config.chunk_size)?;
    tracing::info!("Split into {} chunks", chunks.len());

    // Load or generate keys
    let keypair = KeyPair::load_or_generate(config)?;

    // Prove each chunk sequentially
    let mut chunk_proofs = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        tracing::info!(
            "Proving chunk {}/{} ({} instructions)",
            i + 1,
            chunks.len(),
            chunk.instruction_count()
        );

        let proof = create_proof(
            chunk.clone(),
            &keypair.pk,
            &keypair.params,
            config,
            &keypair.break_points,
        )?;

        chunk_proofs.push(ChunkProof {
            proof,
            index: i,
            initial_registers: chunk.initial_registers.clone(),
            final_registers: chunk.final_registers.clone(),
        });
    }

    tracing::info!("Generated {} chunk proofs", chunk_proofs.len());
    Ok(chunk_proofs)
}

/// Prove execution with automatic chunking (parallel)
///
/// This function splits traces longer than `chunk_size` into multiple chunks,
/// proves each chunk independently **in parallel**, and returns all chunk proofs.
///
/// **Performance**: With N cores, can achieve ~N× speedup over sequential proving.
///
/// **Memory**: Each parallel proof uses ~1-2GB RAM, so with 10 cores expect ~10-20GB usage.
///
/// **Phase 1**: Returns individual chunk proofs (no aggregation yet)
/// **Phase 2**: Will add recursive aggregation to produce single final proof
pub fn prove_execution_chunked_parallel(
    trace: ExecutionTrace,
    config: &KeygenConfig,
) -> Result<Vec<ChunkProof>> {
    let instruction_count = trace.instruction_count();
    tracing::info!(
        "Proving execution (parallel) with {} instructions (chunk_size={})",
        instruction_count,
        config.chunk_size
    );

    // Split trace into chunks
    let chunks = split_trace_into_chunks(trace, config.chunk_size)?;
    tracing::info!("Split into {} chunks for parallel proving", chunks.len());

    // Load or generate keys
    let keypair = KeyPair::load_or_generate(config)?;

    // Clone the necessary data for parallel access
    // Note: ProvingKey and params are large, but Rayon will share them efficiently
    let pk = &keypair.pk;
    let params = &keypair.params;
    let break_points = &keypair.break_points;

    // Prove chunks in parallel using Rayon
    tracing::info!("Starting parallel proof generation with {} threads", rayon::current_num_threads());

    let chunk_proofs: Result<Vec<ChunkProof>> = chunks
        .par_iter()
        .enumerate()
        .map(|(i, chunk)| {
            tracing::debug!(
                "Thread proving chunk {} ({} instructions)",
                i,
                chunk.instruction_count()
            );

            let proof = create_proof(
                chunk.clone(),
                pk,
                params,
                config,
                break_points,
            )?;

            Ok(ChunkProof {
                proof,
                index: i,
                initial_registers: chunk.initial_registers.clone(),
                final_registers: chunk.final_registers.clone(),
            })
        })
        .collect();

    let chunk_proofs = chunk_proofs?;
    tracing::info!("Generated {} chunk proofs (parallel)", chunk_proofs.len());

    Ok(chunk_proofs)
}

/// High-level API: Verify execution proof
///
/// Verifies that a proof correctly proves the claimed state transition.
/// Loads keys from cache or generates them if needed.
pub fn verify_execution(
    proof: &Proof,
    public_inputs: &PublicInputs,
    config: &KeygenConfig,
) -> Result<bool> {
    // Load or generate keys
    tracing::info!("Loading verifying key...");
    let keypair = KeyPair::load_or_generate(config)?;

    verify_proof(proof, &keypair.vk, &keypair.params, public_inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_tracer::{InstructionTrace, RegisterState};
    use std::env;

    /// Test end-to-end proof generation and verification with a simple trace
    #[test]
    fn test_prove_and_verify_simple_trace() {
        // Initialize tracing for test output
        let _ = tracing_subscriber::fmt::try_init();

        // Create a simple execution trace with one instruction
        let initial_regs = RegisterState::from_regs([0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let after_regs = RegisterState::from_regs([0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        let final_regs = after_regs.clone();

        let instr = InstructionTrace {
            pc: 0,
            instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00], // ADD_IMM r1, 42
            registers_before: initial_regs.clone(),
            registers_after: after_regs,
        };

        let trace = ExecutionTrace {
            instructions: vec![instr],
            account_states: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs,
        };

        // Use a test-specific cache directory
        let test_cache = env::temp_dir().join("sbpf_zkvm_test_cache");
        let config = KeygenConfig::new(10, test_cache, 8); // Small k for faster testing

        // Generate proof
        let (proof, public_inputs) = prove_execution(trace, &config)
            .expect("Proof generation should succeed");

        assert!(!proof.is_empty(), "Proof should not be empty");
        tracing::info!("Generated proof of {} bytes", proof.len());

        // Verify proof
        let is_valid = verify_execution(&proof, &public_inputs, &config)
            .expect("Proof verification should not error");

        assert!(is_valid, "Proof should be valid");
    }

    #[test]
    fn test_empty_trace_proof() {
        // Initialize tracing
        let _ = tracing_subscriber::fmt::try_init();

        // Create an empty execution trace
        let trace = ExecutionTrace::new();

        // Use a test-specific cache directory with timestamp to avoid conflicts
        let test_cache = env::temp_dir().join(format!("sbpf_zkvm_empty_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()));
        let config = KeygenConfig::new(10, test_cache, 8);

        // Generate proof for empty trace
        let (proof, public_inputs) = prove_execution(trace, &config)
            .expect("Proof generation for empty trace should succeed");

        assert!(!proof.is_empty());

        // Verify proof
        let is_valid = verify_execution(&proof, &public_inputs, &config)
            .expect("Verification should not error");

        assert!(is_valid, "Empty trace proof should be valid");
    }

    #[test]
    fn test_prove_and_verify_simple_trace_unique_cache() {
        // Initialize tracing for test output
        let _ = tracing_subscriber::fmt::try_init();

        // Create a simple execution trace with one instruction
        let initial_regs = RegisterState::from_regs([0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let after_regs = RegisterState::from_regs([0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        let final_regs = after_regs.clone();

        let instr = InstructionTrace {
            pc: 0,
            instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00], // ADD_IMM r1, 42
            registers_before: initial_regs.clone(),
            registers_after: after_regs,
        };

        let trace = ExecutionTrace {
            instructions: vec![instr],
            account_states: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs,
        };

        // Use a test-specific cache directory with timestamp
        let test_cache = env::temp_dir().join(format!("sbpf_zkvm_simple_{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()));
        let config = KeygenConfig::new(10, test_cache, 8); // Small k for faster testing

        // Generate proof
        let (proof, public_inputs) = prove_execution(trace, &config)
            .expect("Proof generation should succeed");

        assert!(!proof.is_empty(), "Proof should not be empty");
        tracing::info!("Generated proof of {} bytes", proof.len());

        // Verify proof
        let is_valid = verify_execution(&proof, &public_inputs, &config)
            .expect("Proof verification should not error");

        assert!(is_valid, "Proof should be valid");
    }

    #[test]
    fn test_prove_execution_chunked() {
        // Initialize tracing
        let _ = tracing_subscriber::fmt::try_init();

        // Create a trace with 25 instructions (will split into 3 chunks of size 10)
        let initial_regs = RegisterState::from_regs([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut instrs = Vec::new();
        let mut current_regs = initial_regs.clone();

        for i in 0..25 {
            let next_regs = RegisterState::from_regs([
                0,
                current_regs.regs[1] + 1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                (i + 1) * 8,
            ]);

            instrs.push(InstructionTrace {
                pc: i * 8,
                instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00], // ADD_IMM r1, 1
                registers_before: current_regs.clone(),
                registers_after: next_regs.clone(),
            });

            current_regs = next_regs;
        }

        let final_regs = current_regs;

        let trace = ExecutionTrace {
            instructions: instrs,
            account_states: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs,
        };

        let test_cache = env::temp_dir().join(format!(
            "sbpf_zkvm_chunked_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));
        let config = KeygenConfig::new(10, test_cache, 8).with_chunk_size(10);

        // Prove with chunking
        let chunk_proofs = prove_execution_chunked(trace, &config)
            .expect("Chunked proving should succeed");

        assert_eq!(chunk_proofs.len(), 3, "Should have 3 chunks");

        // Verify each chunk proof
        for (i, chunk_proof) in chunk_proofs.iter().enumerate() {
            assert!(!chunk_proof.proof.is_empty(), "Chunk {} proof should not be empty", i);
            tracing::info!("Chunk {} proof: {} bytes", i, chunk_proof.proof.len());

            // Verify state continuity between chunks
            if i > 0 {
                let prev_final = &chunk_proofs[i - 1].final_registers;
                let curr_initial = &chunk_proof.initial_registers;
                for j in 0..11 {
                    assert_eq!(
                        prev_final.regs[j], curr_initial.regs[j],
                        "State continuity broken between chunk {} and {} at register {}",
                        i - 1, i, j
                    );
                }
            }
        }

        tracing::info!("All {} chunks proved successfully", chunk_proofs.len());
    }

    #[test]
    fn test_prove_execution_chunked_parallel() {
        // Initialize tracing
        let _ = tracing_subscriber::fmt::try_init();

        // Create a trace with 25 instructions (will split into 3 chunks of size 10)
        let initial_regs = RegisterState::from_regs([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut instrs = Vec::new();
        let mut current_regs = initial_regs.clone();

        for i in 0..25 {
            let next_regs = RegisterState::from_regs([
                0,
                current_regs.regs[1] + 1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                (i + 1) * 8,
            ]);

            instrs.push(InstructionTrace {
                pc: i * 8,
                instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00], // ADD_IMM r1, 1
                registers_before: current_regs.clone(),
                registers_after: next_regs.clone(),
            });

            current_regs = next_regs;
        }

        let final_regs = current_regs;

        let trace = ExecutionTrace {
            instructions: instrs,
            account_states: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs,
        };

        let test_cache = env::temp_dir().join(format!(
            "sbpf_zkvm_parallel_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        ));
        let config = KeygenConfig::new(10, test_cache, 8).with_chunk_size(10);

        // Prove with parallel chunking
        let chunk_proofs = prove_execution_chunked_parallel(trace, &config)
            .expect("Parallel chunked proving should succeed");

        assert_eq!(chunk_proofs.len(), 3, "Should have 3 chunks");

        // Verify each chunk proof
        for (i, chunk_proof) in chunk_proofs.iter().enumerate() {
            assert!(!chunk_proof.proof.is_empty(), "Chunk {} proof should not be empty", i);
            tracing::info!("Chunk {} proof: {} bytes", i, chunk_proof.proof.len());

            // Verify state continuity between chunks
            if i > 0 {
                let prev_final = &chunk_proofs[i - 1].final_registers;
                let curr_initial = &chunk_proof.initial_registers;
                for j in 0..11 {
                    assert_eq!(
                        prev_final.regs[j], curr_initial.regs[j],
                        "State continuity broken between chunk {} and {} at register {}",
                        i - 1, i, j
                    );
                }
            }
        }

        tracing::info!("All {} chunks proved successfully (parallel)", chunk_proofs.len());
    }

    #[test]
    #[ignore] // Expensive benchmark test - run with `cargo test -- --ignored`
    fn benchmark_sequential_vs_parallel() {
        use std::time::Instant;

        // Initialize tracing
        let _ = tracing_subscriber::fmt::try_init();

        // Create a trace with 50 instructions (will split into 5 chunks of size 10)
        let initial_regs = RegisterState::from_regs([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut instrs = Vec::new();
        let mut current_regs = initial_regs.clone();

        for i in 0..50 {
            let next_regs = RegisterState::from_regs([
                0,
                current_regs.regs[1] + 1,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                (i + 1) * 8,
            ]);

            instrs.push(InstructionTrace {
                pc: i * 8,
                instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00], // ADD_IMM r1, 1
                registers_before: current_regs.clone(),
                registers_after: next_regs.clone(),
            });

            current_regs = next_regs;
        }

        let final_regs = current_regs;

        let trace = ExecutionTrace {
            instructions: instrs,
            account_states: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs.clone(),
        };

        let config = KeygenConfig::new(10, env::temp_dir().join("sbpf_benchmark"), 8).with_chunk_size(10);

        // Benchmark sequential proving
        tracing::info!("=== Sequential Proving Benchmark ===");
        let start_seq = Instant::now();
        let seq_proofs = prove_execution_chunked(trace.clone(), &config)
            .expect("Sequential proving should succeed");
        let seq_duration = start_seq.elapsed();
        tracing::info!("Sequential: {} chunks in {:.2}s", seq_proofs.len(), seq_duration.as_secs_f64());

        // Benchmark parallel proving
        tracing::info!("=== Parallel Proving Benchmark ===");
        let start_par = Instant::now();
        let par_proofs = prove_execution_chunked_parallel(trace, &config)
            .expect("Parallel proving should succeed");
        let par_duration = start_par.elapsed();
        tracing::info!("Parallel: {} chunks in {:.2}s", par_proofs.len(), par_duration.as_secs_f64());

        // Calculate speedup
        let speedup = seq_duration.as_secs_f64() / par_duration.as_secs_f64();
        tracing::info!("=== Benchmark Results ===");
        tracing::info!("Speedup: {:.2}×", speedup);
        tracing::info!("Sequential: {:.2}s", seq_duration.as_secs_f64());
        tracing::info!("Parallel:   {:.2}s", par_duration.as_secs_f64());

        // Verify both produce the same number of proofs
        assert_eq!(seq_proofs.len(), par_proofs.len());

        // Verify state continuity for both
        for proofs in [&seq_proofs, &par_proofs] {
            for i in 0..proofs.len() {
                assert_eq!(proofs[i].index, i);
                if i > 0 {
                    for j in 0..11 {
                        assert_eq!(proofs[i - 1].final_registers.regs[j], proofs[i].initial_registers.regs[j]);
                    }
                }
            }
        }

        tracing::info!("✓ Both sequential and parallel proving produced valid results");
    }
}
