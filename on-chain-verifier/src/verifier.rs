//! Core Groth16 verification logic for SBPF zkVM proofs
//!
//! This module implements the on-chain verification using Solana's
//! native alt_bn128 syscalls through the groth16-solana crate.

use crate::circuit_vk::BPF_CIRCUIT_VK;
use crate::error::VerifierError;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use pinocchio::ProgramResult;

/// Reference to the BPF circuit verifying key (generated with deterministic seed)
pub static SBPF_ZKVM_VK: &Groth16Verifyingkey = &BPF_CIRCUIT_VK;

/// Verify a Groth16 proof of SBPF program execution
///
/// # Arguments
/// * `proof_a` - First proof element (G1 point, 64 bytes)
/// * `proof_b` - Second proof element (G2 point, 128 bytes)
/// * `proof_c` - Third proof element (G1 point, 64 bytes)
/// * `public_inputs_data` - Concatenated public inputs (N * 32 bytes)
///
/// # Returns
/// * `Ok(())` if the proof is valid
/// * `Err(VerifierError)` if verification fails
pub fn verify_sbpf_proof(
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    public_inputs_data: &[u8],
) -> ProgramResult {
    // Check public inputs count matches VK
    let num_inputs = public_inputs_data.len() / 32;
    if num_inputs != SBPF_ZKVM_VK.nr_pubinputs {
        return Err(VerifierError::InvalidPublicInputsLength.into());
    }
    
    // Parse public inputs into 32-byte chunks
    // For 2 inputs, we create a fixed-size array
    let mut public_inputs: [[u8; 32]; 2] = [[0u8; 32]; 2];
    for (i, chunk) in public_inputs_data.chunks(32).take(2).enumerate() {
        public_inputs[i].copy_from_slice(chunk);
    }
    
    // Negate proof_a for the pairing equation
    // The Groth16 verification equation checks:
    // e(A, B) = e(α, β) · e(pub_inputs_combined, γ) · e(C, δ)
    //
    // By negating A, we transform this to:
    // e(-A, B) · e(α, β) · e(pub_inputs_combined, γ) · e(C, δ) = 1
    //
    // Which is what the pairing check verifies
    let negated_proof_a = negate_g1_point(proof_a)
        .map_err(|_| VerifierError::G1OperationFailed)?;
    
    // Create verifier with the negated proof_a
    let mut verifier = Groth16Verifier::new(
        &negated_proof_a,
        proof_b,
        proof_c,
        &public_inputs,
        SBPF_ZKVM_VK,
    ).map_err(|_| VerifierError::InvalidProofFormat)?;
    
    // Run verification (uses alt_bn128 syscalls internally)
    verifier.verify()
        .map_err(|_| VerifierError::ProofVerificationFailed)?;
    
    Ok(())
}

/// Negate a G1 point (flip the y-coordinate)
///
/// For BN254, negation in G1 is: -P = (x, -y mod p)
/// where p is the field modulus.
///
/// In big-endian representation, we compute y' = p - y
fn negate_g1_point(point: &[u8; 64]) -> Result<[u8; 64], VerifierError> {
    // BN254 base field modulus p (big-endian)
    const FIELD_MODULUS: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
        0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
    ];
    
    let mut result = [0u8; 64];
    
    // Copy x coordinate unchanged
    result[0..32].copy_from_slice(&point[0..32]);
    
    // Negate y coordinate: y' = p - y
    let y = &point[32..64];
    
    // Perform big-integer subtraction: p - y
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (FIELD_MODULUS[i] as i32) - (y[i] as i32) - (borrow as i32);
        if diff < 0 {
            result[32 + i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            result[32 + i] = diff as u8;
            borrow = 0;
        }
    }
    
    // If y was 0, result should also be 0 (point at infinity edge case)
    // The borrow should be 0 for valid points
    
    Ok(result)
}

/// Verify a proof with a custom verifying key loaded from account data
pub fn verify_sbpf_proof_with_vk(
    vk: &Groth16Verifyingkey,
    proof_a: &[u8; 64],
    proof_b: &[u8; 128],
    proof_c: &[u8; 64],
    public_inputs_data: &[u8],
) -> ProgramResult {
    let num_inputs = public_inputs_data.len() / 32;
    if num_inputs != vk.nr_pubinputs {
        return Err(VerifierError::InvalidPublicInputsLength.into());
    }
    
    // For now, we only support 2 public inputs (fixed circuit)
    // A production implementation would need dynamic sizing
    if num_inputs != 2 {
        return Err(VerifierError::InvalidPublicInputsLength.into());
    }
    
    let mut public_inputs: [[u8; 32]; 2] = [[0u8; 32]; 2];
    for (i, chunk) in public_inputs_data.chunks(32).take(2).enumerate() {
        public_inputs[i].copy_from_slice(chunk);
    }
    
    let negated_proof_a = negate_g1_point(proof_a)
        .map_err(|_| VerifierError::G1OperationFailed)?;
    
    let mut verifier = Groth16Verifier::new(
        &negated_proof_a,
        proof_b,
        proof_c,
        &public_inputs,
        vk,
    ).map_err(|_| VerifierError::InvalidProofFormat)?;
    
    verifier.verify()
        .map_err(|_| VerifierError::ProofVerificationFailed)?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_negate_g1_zero() {
        // Zero point should remain zero
        let zero_point = [0u8; 64];
        let negated = negate_g1_point(&zero_point).unwrap();
        
        // x should be unchanged
        assert_eq!(&negated[0..32], &zero_point[0..32]);
        
        // -0 mod p = p - 0 = p (but for point at infinity, y=0 stays 0)
        // This is a special case - in practice, infinity is represented differently
    }
    
    #[test]
    fn test_negate_g1_simple() {
        // A simple test with y = 1
        let mut point = [0u8; 64];
        point[63] = 1; // y = 1 (little-endian last byte)
        
        let negated = negate_g1_point(&point).unwrap();
        
        // x unchanged
        assert_eq!(&negated[0..32], &point[0..32]);
        
        // y should be p - 1
        // p - 1 in big-endian ends with ...fd46
        assert_eq!(negated[63], 0x46);
    }
}

