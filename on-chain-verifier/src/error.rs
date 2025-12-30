//! Error types for the SBPF zkVM on-chain verifier

use pinocchio::program_error::ProgramError;

/// Errors that can occur during proof verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VerifierError {
    /// Proof bytes have invalid length (expected 260)
    InvalidProofLength = 0,
    
    /// Proof format is invalid (failed to parse G1/G2 points)
    InvalidProofFormat = 1,
    
    /// Public inputs have invalid length (must be multiple of 32)
    InvalidPublicInputsLength = 2,
    
    /// Public input exceeds BN254 field size
    PublicInputOverflow = 3,
    
    /// Groth16 proof verification failed
    ProofVerificationFailed = 4,
    
    /// Verifying key not found or invalid
    InvalidVerifyingKey = 5,
    
    /// G1 point operation failed
    G1OperationFailed = 6,
    
    /// G2 point operation failed  
    G2OperationFailed = 7,
    
    /// Pairing check failed
    PairingFailed = 8,
    
    /// Feature not yet implemented
    NotImplemented = 99,
}

impl From<VerifierError> for ProgramError {
    fn from(e: VerifierError) -> Self {
        // Custom error codes start at a high offset to avoid collision
        ProgramError::Custom(6000 + e as u32)
    }
}

impl VerifierError {
    /// Get a human-readable description of the error
    pub fn description(&self) -> &'static str {
        match self {
            VerifierError::InvalidProofLength => "Proof has invalid length",
            VerifierError::InvalidProofFormat => "Proof format is invalid",
            VerifierError::InvalidPublicInputsLength => "Public inputs have invalid length",
            VerifierError::PublicInputOverflow => "Public input exceeds field size",
            VerifierError::ProofVerificationFailed => "Proof verification failed",
            VerifierError::InvalidVerifyingKey => "Invalid verifying key",
            VerifierError::G1OperationFailed => "G1 point operation failed",
            VerifierError::G2OperationFailed => "G2 point operation failed",
            VerifierError::PairingFailed => "Pairing check failed",
            VerifierError::NotImplemented => "Feature not implemented",
        }
    }
}


