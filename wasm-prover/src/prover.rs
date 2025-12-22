//! Proof Generation and Verification
//!
//! Single-threaded Halo2 proof generation for WASM.

use crate::trace::ExecutionTrace;
use crate::circuit::CounterCircuit;
use crate::keys::{get_params, get_proving_key, get_verifying_key};
use halo2_axiom::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{create_proof as halo2_create_proof, verify_proof as halo2_verify_proof},
    poly::kzg::{
        commitment::KZGCommitmentScheme,
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255,
        TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    poly::commitment::ParamsProver,
};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::{Sha256, Digest};

/// Create a proof for the given execution trace
pub fn create_proof(trace: &ExecutionTrace) -> Result<Vec<u8>, String> {
    tracing::info!("Creating proof for {} instructions", trace.instructions.len());
    
    // Get keys (generates if needed - cached for subsequent calls)
    let params = get_params();
    let pk = get_proving_key();
    
    // Create circuit from trace
    let circuit = CounterCircuit::new(trace.clone());
    
    tracing::info!("Generating Halo2 proof...");
    
    // Use deterministic RNG seeded from trace hash
    let trace_hash = compute_trace_hash(trace);
    let rng = StdRng::from_seed(trace_hash);
    
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    
    halo2_create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<_>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, _>,
        _,
    >(params, pk, &[circuit], &[&[]], rng, &mut transcript)
        .map_err(|e| format!("Proof generation failed: {:?}", e))?;
    
    let proof = transcript.finalize();
    
    tracing::info!("Proof generated: {} bytes", proof.len());
    
    Ok(proof)
}

/// Verify a proof
pub fn verify_proof(
    proof: &[u8],
    _initial_value: u64,
    _final_value: u64,
) -> Result<bool, String> {
    tracing::info!("Verifying proof ({} bytes)", proof.len());
    
    let params = get_params();
    let vk = get_verifying_key();
    
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    
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

/// Compute a hash of the execution trace for deterministic RNG seeding
fn compute_trace_hash(trace: &ExecutionTrace) -> [u8; 32] {
    let mut hasher = Sha256::new();
    
    for reg in &trace.initial_registers.regs {
        hasher.update(reg.to_le_bytes());
    }
    
    for reg in &trace.final_registers.regs {
        hasher.update(reg.to_le_bytes());
    }
    
    hasher.update((trace.instructions.len() as u64).to_le_bytes());
    
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interpreter::execute_counter;
    
    #[test]
    fn test_create_and_verify_proof() {
        let trace = execute_counter(42).expect("Execution should succeed");
        
        let proof = create_proof(&trace).expect("Proof should be created");
        assert!(!proof.is_empty());
        
        let valid = verify_proof(&proof, 42, 43).expect("Verification should not error");
        assert!(valid);
    }
}
