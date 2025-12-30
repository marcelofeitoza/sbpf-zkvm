//! On-chain Groth16 verifier for SBPF zkVM proofs
//!
//! This crate provides on-chain verification of zero-knowledge proofs
//! that attest to correct BPF program execution. It uses Solana's
//! native alt_bn128 syscalls for efficient pairing-based verification.
//!
//! # Architecture
//!
//! The verification flow:
//! 1. Client generates a trace of BPF program execution
//! 2. Client proves the trace off-chain (browser/WASM or native)
//! 3. Client submits proof + public inputs to this on-chain verifier
//! 4. Verifier checks the Groth16 proof using alt_bn128 syscalls
//! 5. If valid, downstream program logic can trust the execution claim
//!
//! # Public Inputs Structure
//!
//! The proof attests to a BPF execution trace with the following public claims:
//! - `initial_state_hash`: Hash of initial register/memory state
//! - `final_state_hash`: Hash of final register/memory state
//! - Additional program-specific claims (e.g., account state changes)

#![cfg_attr(not(feature = "std"), no_std)]

use five8_const::decode_32_const;
#[allow(unused_imports)]
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use pinocchio::{
    account_info::AccountInfo,
    default_allocator, default_panic_handler, program_entrypoint,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

pub mod circuit_vk;
pub mod error;
pub mod state;
pub mod verifier;

use error::VerifierError;
use verifier::verify_sbpf_proof;

/// Program ID - actual deployed address
pub const ID: [u8; 32] = decode_32_const("E2fQNEm4azB6odaSPX7mAMHE4K7CW1dmJq8KN6KUfieM");

program_entrypoint!(process_instruction);
default_allocator!();
default_panic_handler!();

/// Instruction discriminators
#[repr(u8)]
pub enum Instruction {
    /// Verify a Groth16 proof of BPF execution
    /// 
    /// Data layout:
    /// - [0]: Instruction discriminator (0x00)
    /// - [1..261]: Groth16 proof (260 bytes: A=64, B=128, C=64 + 4 padding)
    /// - [261..]: Public inputs (N * 32 bytes)
    VerifyProof = 0,
    
    /// Verify and execute - verify proof then call downstream program
    /// 
    /// Data layout:
    /// - [0]: Instruction discriminator (0x01)
    /// - [1..261]: Groth16 proof
    /// - [261..?]: Public inputs
    /// - Remaining: CPI instruction data for downstream program
    VerifyAndExecute = 1,
}

impl TryFrom<&u8> for Instruction {
    type Error = ProgramError;
    
    fn try_from(value: &u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Instruction::VerifyProof),
            1 => Ok(Instruction::VerifyAndExecute),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Verify program ID
    let expected_program_id = Pubkey::from(ID);
    if program_id != &expected_program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    
    // Parse instruction
    let (discriminator, instruction_data) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    
    match Instruction::try_from(discriminator)? {
        Instruction::VerifyProof => {
            process_verify_proof(accounts, instruction_data)
        }
        Instruction::VerifyAndExecute => {
            process_verify_and_execute(accounts, instruction_data)
        }
    }
}

/// Process a standalone proof verification
fn process_verify_proof(
    _accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Minimum data: 260 (proof) + 32 (at least one public input)
    if data.len() < 260 + 32 {
        return Err(VerifierError::InvalidProofLength.into());
    }
    
    let (proof_bytes, public_inputs_data) = data.split_at(260);
    
    // Parse proof components
    // Standard Groth16: A (64 bytes G1), B (128 bytes G2), C (64 bytes G1)
    // SP1 adds 4 bytes padding at the end
    let proof_a: &[u8; 64] = proof_bytes[0..64]
        .try_into()
        .map_err(|_| VerifierError::InvalidProofFormat)?;
    let proof_b: &[u8; 128] = proof_bytes[64..192]
        .try_into()
        .map_err(|_| VerifierError::InvalidProofFormat)?;
    let proof_c: &[u8; 64] = proof_bytes[192..256]
        .try_into()
        .map_err(|_| VerifierError::InvalidProofFormat)?;
    
    // Parse public inputs (each is 32 bytes, big-endian field element)
    if public_inputs_data.len() % 32 != 0 {
        return Err(VerifierError::InvalidPublicInputsLength.into());
    }
    
    // Verify the proof
    verify_sbpf_proof(proof_a, proof_b, proof_c, public_inputs_data)?;
    
    Ok(())
}

/// Process verify + execute downstream CPI
fn process_verify_and_execute(
    _accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    // TODO: Implement CPI after verification
    // This would allow atomic verify-then-transfer patterns
    Err(VerifierError::NotImplemented.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_instruction_discriminator() {
        assert_eq!(Instruction::try_from(&0u8).unwrap() as u8, 0);
        assert_eq!(Instruction::try_from(&1u8).unwrap() as u8, 1);
        assert!(Instruction::try_from(&2u8).is_err());
    }
}

