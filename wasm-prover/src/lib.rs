//! WASM zkVM Prover
//!
//! Browser-based zero-knowledge prover for Solana BPF programs.
//! Generates Halo2 proofs entirely client-side - no private data leaves the browser.
//!
//! # Security Model
//! - Witness data never crosses the JS boundary
//! - Execution trace stays in WASM memory
//! - Only proof bytes are returned to JavaScript
//!
//! # Syscall Support
//! Only whitelisted logging syscalls are supported:
//! - sol_log_
//! - sol_log_64_
//! - sol_log_pubkey_
//! - sol_log_compute_units_
//!
//! Unknown syscalls will cause validation to fail.
//!
//! # What This Circuit Proves
//! The circuit proves that:
//! 1. A sequence of BPF instructions was executed
//! 2. Register transitions are internally consistent
//! 3. All syscalls returned 0 (success) and preserved callee-saved registers
//!
//! The circuit does NOT prove:
//! - Instruction semantics (ADD actually adds, etc.)
//! - Memory consistency
//! - Account state changes (no state commitments)
//! - Program correctness

mod circuit;
mod prover;
mod keys;

use wasm_bindgen::prelude::*;
use trace_core::{binary, SyscallPolicy};

#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
    
    tracing_wasm::set_as_global_default();
    
    tracing::info!("WASM zkVM Prover initialized (strict syscall whitelist)");
}

/// Generate a ZK proof from a trace file
///
/// # Security
/// The trace and witness NEVER leave WASM memory.
/// Only the proof (which reveals nothing about the witness) is returned.
///
/// # Validation
/// Traces are validated with strict syscall policy:
/// - Only whitelisted logging syscalls allowed
/// - Unknown syscalls will fail validation
#[wasm_bindgen]
pub fn prove_trace(trace_bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    tracing::info!("Proving from trace ({} bytes)", trace_bytes.len());
    
    let start = web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now());
    
    // Deserialize trace
    let trace = binary::deserialize(trace_bytes)
        .map_err(|e| JsError::new(&format!("Failed to deserialize trace: {}", e)))?;
    
    tracing::info!(
        "Loaded trace: {} steps ({} instructions, {} syscalls, {} unknown)", 
        trace.step_count(),
        trace.instruction_count(),
        trace.syscall_count(),
        trace.unknown_syscall_count()
    );
    
    // Validate with strict policy
    let policy = SyscallPolicy::strict();
    trace.validate_with_policy(&policy)
        .map_err(|e| JsError::new(&format!("Trace validation failed: {}", e)))?;
    
    tracing::info!("Trace validation passed (strict policy)");
    
    // Generate proof
    let proof = prover::create_proof(&trace)
        .map_err(|e| JsError::new(&format!("Proof generation failed: {}", e)))?;
    
    if let Some(start_time) = start {
        let end = web_sys::window()
            .and_then(|w| w.performance())
            .map(|p| p.now())
            .unwrap_or(0.0);
        tracing::info!("Proof generated in {:.2}s ({} bytes)", (end - start_time) / 1000.0, proof.len());
    }
    
    Ok(proof)
}

/// Verify a proof against a trace
#[wasm_bindgen]
pub fn verify_trace_proof(proof: &[u8], trace_bytes: &[u8]) -> Result<bool, JsError> {
    tracing::info!("Verifying proof ({} bytes)", proof.len());
    
    let trace = binary::deserialize(trace_bytes)
        .map_err(|e| JsError::new(&format!("Failed to deserialize trace: {}", e)))?;
    
    prover::verify_proof(proof, &trace)
        .map_err(|e| JsError::new(&format!("Verification failed: {}", e)))
}

/// Get detailed trace info for UI display
#[wasm_bindgen]
pub fn get_trace_info(trace_bytes: &[u8]) -> Result<JsValue, JsError> {
    let trace = binary::deserialize(trace_bytes)
        .map_err(|e| JsError::new(&format!("Failed to deserialize trace: {}", e)))?;
    
    let policy = SyscallPolicy::strict();
    let validation = trace.validation_result(&policy);
    
    let info = serde_json::json!({
        "step_count": trace.step_count(),
        "instruction_count": trace.instruction_count(),
        "syscall_count": trace.syscall_count(),
        "initial_r0": trace.initial_registers.regs[0],
        "final_r0": trace.final_registers.regs[0],
        "validation": if validation.valid { "valid" } else { "invalid" },
        "validation_error": validation.error,
        "syscalls": {
            "total": validation.syscall_summary.total,
            "whitelisted": validation.syscall_summary.whitelisted,
            "unknown": validation.syscall_summary.unknown,
            "unique_hashes": validation.syscall_summary.unique_hashes,
            "all_whitelisted": validation.syscall_summary.unknown == 0,
        }
    });
    
    Ok(JsValue::from_str(&info.to_string()))
}

/// Get prover capabilities and limitations
#[wasm_bindgen]
pub fn get_prover_info() -> JsValue {
    let info = serde_json::json!({
        "name": "WASM zkVM Prover",
        "version": env!("CARGO_PKG_VERSION"),
        "proof_system": "Halo2 (KZG)",
        "circuit_k": keys::CIRCUIT_K,
        "chunk_size": keys::CHUNK_SIZE,
        "trace_format": "SBPFZK02",
        
        // Syscall whitelist
        "whitelisted_syscalls": SyscallPolicy::all_allowed(),
        
        // What we prove
        "proves": [
            "Execution trace consistency",
            "Register state transitions",
            "Syscall return values (r0 == 0)",
            "Callee-saved register preservation across syscalls"
        ],
        
        // What we do NOT prove
        "does_not_prove": [
            "Instruction semantics correctness",
            "Memory read/write consistency",
            "Account state changes",
            "Counter value changes",
            "Program bytecode authenticity"
        ],
        
        // Limitations
        "limitations": [
            "Only logging syscalls supported",
            "No memory effect syscalls",
            "No state commitments",
            "Fixed chunk size"
        ]
    });
    
    JsValue::from_str(&info.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;
    use trace_core::{ExecutionTrace, Step, InstructionTrace, SyscallTrace, SyscallId, RegisterState};
    
    wasm_bindgen_test_configure!(run_in_browser);
    
    #[wasm_bindgen_test]
    fn test_reject_unknown_syscall() {
        let mut trace = ExecutionTrace::new();
        trace.steps.push(Step::Syscall(SyscallTrace {
            pc: 0,
            syscall_id: SyscallId::Unknown(0x12345678),
            raw_hash: 0x12345678,
            return_value: 0,
            registers_before: RegisterState::new(),
            registers_after: RegisterState::new(),
        }));
        
        let trace_bytes = binary::serialize(&trace);
        let result = prove_trace(&trace_bytes);
        
        // Should fail because unknown syscalls are not allowed
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Unsupported syscall"));
    }
    
    #[wasm_bindgen_test]
    fn test_accept_whitelisted_syscall() {
        let mut trace = ExecutionTrace::new();
        trace.steps.push(Step::Syscall(SyscallTrace {
            pc: 0,
            syscall_id: SyscallId::SolLog,
            raw_hash: 0,
            return_value: 0,
            registers_before: RegisterState::new(),
            registers_after: RegisterState::new(),
        }));
        
        let trace_bytes = binary::serialize(&trace);
        let info: serde_json::Value = serde_json::from_str(
            &get_trace_info(&trace_bytes).unwrap().as_string().unwrap()
        ).unwrap();
        
        assert_eq!(info["validation"], "valid");
        assert_eq!(info["syscalls"]["all_whitelisted"], true);
    }
}
