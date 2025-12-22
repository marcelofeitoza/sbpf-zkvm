//! Key Management for WASM
//!
//! Handles KZG parameters, proving keys, and verifying keys.

use halo2_axiom::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
};
use crate::circuit::CounterCircuit;
use std::sync::OnceLock;

/// Circuit size parameter (2^k rows)
pub const CIRCUIT_K: u32 = 8;

/// Chunk size for fixed circuit shape
pub const CHUNK_SIZE: usize = 10;

/// Cached proving key
static PROVING_KEY: OnceLock<ProvingKey<G1Affine>> = OnceLock::new();

/// Cached verifying key
static VERIFYING_KEY: OnceLock<VerifyingKey<G1Affine>> = OnceLock::new();

/// Cached KZG parameters
static PARAMS: OnceLock<ParamsKZG<Bn256>> = OnceLock::new();

/// Get or generate KZG parameters
pub fn get_params() -> &'static ParamsKZG<Bn256> {
    PARAMS.get_or_init(|| {
        tracing::info!("Generating KZG parameters for k={}", CIRCUIT_K);
        ParamsKZG::<Bn256>::setup(CIRCUIT_K, rand::thread_rng())
    })
}

/// Get or generate proving key
pub fn get_proving_key() -> &'static ProvingKey<G1Affine> {
    PROVING_KEY.get_or_init(|| {
        tracing::info!("Generating proving key...");
        generate_keys().0
    })
}

/// Get or generate verifying key
pub fn get_verifying_key() -> &'static VerifyingKey<G1Affine> {
    VERIFYING_KEY.get_or_init(|| {
        tracing::info!("Generating verifying key...");
        generate_keys().1
    })
}

/// Generate both proving and verifying keys
fn generate_keys() -> (ProvingKey<G1Affine>, VerifyingKey<G1Affine>) {
    let params = get_params();
    
    // Create dummy circuit for keygen
    let circuit = CounterCircuit::dummy();
    
    // Generate verifying key
    tracing::info!("Computing verifying key...");
    let vk = keygen_vk(params, &circuit)
        .expect("VK generation failed");
    
    // Generate proving key
    tracing::info!("Computing proving key...");
    let pk = keygen_pk(params, vk.clone(), &circuit)
        .expect("PK generation failed");
    
    tracing::info!("Key generation complete");
    
    (pk, vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_axiom::poly::commitment::Params;
    
    #[test]
    fn test_params_generation() {
        let params = get_params();
        assert!(params.k() == CIRCUIT_K);
    }
}
