//! WASM zkVM Prover
//!
//! Browser-based zero-knowledge prover for Solana BPF programs.
//! Generates Halo2 proofs entirely client-side - no private data leaves the browser.
//!
//! # Security Model
//! - Witness data never crosses the JS boundary
//! - Execution trace stays in WASM memory
//! - Only proof bytes are returned to JavaScript

mod interpreter;
mod trace;
mod circuit;
mod prover;
mod keys;

use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages in browser console
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
    
    // Initialize tracing for WASM
    tracing_wasm::set_as_global_default();
    
    tracing::info!("WASM zkVM Prover initialized");
}

/// Generate a ZK proof for the counter program
///
/// This function:
/// 1. Executes the counter program with the given initial value
/// 2. Generates an execution trace (private - stays in WASM)
/// 3. Creates a Halo2 proof
/// 4. Returns only the proof bytes
///
/// # Arguments
/// * `initial_value` - The initial counter value (will be incremented)
///
/// # Returns
/// * Proof bytes as Uint8Array
///
/// # Security
/// The witness and execution trace NEVER leave WASM memory.
/// Only the proof (which reveals nothing about the witness) is returned.
#[wasm_bindgen]
pub fn prove_counter(initial_value: u64) -> Result<Vec<u8>, JsError> {
    tracing::info!("Starting proof generation for counter with initial_value={}", initial_value);
    
    let start = web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now());
    
    // Step 1: Execute counter program and generate trace (PRIVATE)
    let trace = interpreter::execute_counter(initial_value)
        .map_err(|e| JsError::new(&format!("Execution failed: {}", e)))?;
    
    tracing::info!("Executed {} instructions", trace.instructions.len());
    
    // Step 2: Generate proof (witness stays in WASM memory)
    let proof = prover::create_proof(&trace)
        .map_err(|e| JsError::new(&format!("Proof generation failed: {}", e)))?;
    
    if let Some(start_time) = start {
        let end = web_sys::window()
            .and_then(|w| w.performance())
            .map(|p| p.now())
            .unwrap_or(0.0);
        tracing::info!("Proof generated in {:.2}s ({} bytes)", (end - start_time) / 1000.0, proof.len());
    }
    
    // Only the proof bytes cross the JS boundary
    Ok(proof)
}

/// Verify a proof (can be done in browser or server)
///
/// # Arguments
/// * `proof` - The proof bytes
/// * `initial_value` - The claimed initial value
/// * `final_value` - The claimed final value
///
/// # Returns
/// * true if proof is valid, false otherwise
#[wasm_bindgen]
pub fn verify_counter_proof(
    proof: &[u8],
    initial_value: u64,
    final_value: u64,
) -> Result<bool, JsError> {
    tracing::info!("Verifying proof: initial={}, final={}", initial_value, final_value);
    
    prover::verify_proof(proof, initial_value, final_value)
        .map_err(|e| JsError::new(&format!("Verification failed: {}", e)))
}

/// Get information about the prover
#[wasm_bindgen]
pub fn get_prover_info() -> JsValue {
    let info = serde_json::json!({
        "name": "WASM zkVM Prover",
        "version": env!("CARGO_PKG_VERSION"),
        "supported_programs": ["counter"],
        "proof_system": "Halo2 (KZG)",
        "circuit_k": keys::CIRCUIT_K,
        "chunk_size": keys::CHUNK_SIZE,
    });
    
    JsValue::from_str(&info.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    
    wasm_bindgen_test_configure!(run_in_browser);
    
    #[wasm_bindgen_test]
    fn test_prove_counter() {
        let result = prove_counter(42);
        assert!(result.is_ok(), "Proof generation should succeed");
        
        let proof = result.unwrap();
        assert!(!proof.is_empty(), "Proof should not be empty");
    }
    
    #[wasm_bindgen_test]
    fn test_verify_proof() {
        let proof = prove_counter(42).unwrap();
        let valid = verify_counter_proof(&proof, 42, 43).unwrap();
        assert!(valid, "Proof should verify");
    }
}

