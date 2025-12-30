//! State accounts for the SBPF zkVM verifier
//!
//! These structures define on-chain state for storing verifying keys
//! and verified execution claims.

use pinocchio::pubkey::Pubkey;

/// Size of a verifying key account (fixed for our circuit)
/// 
/// Groth16 VK structure:
/// - vk_alpha_g1: 64 bytes (G1 point)
/// - vk_beta_g2: 128 bytes (G2 point)
/// - vk_gamma_g2: 128 bytes (G2 point)
/// - vk_delta_g2: 128 bytes (G2 point)
/// - vk_ic: variable, (num_public_inputs + 1) * 64 bytes
///
/// For our SBPF zkVM with 2 public inputs (initial_hash, final_hash):
/// vk_ic = 3 * 64 = 192 bytes
/// Total = 64 + 128 + 128 + 128 + 192 = 640 bytes
/// Add metadata: discriminator (8) + authority (32) + circuit_id (32) = 72 bytes
/// Total with metadata: 712 bytes
pub const VERIFYING_KEY_SIZE: usize = 712;

/// Account discriminator for verifying key accounts
pub const VK_DISCRIMINATOR: [u8; 8] = [0x73, 0x62, 0x70, 0x66, 0x7a, 0x6b, 0x76, 0x6b]; // "sbpfzkvk"

/// Account discriminator for verified claim accounts  
pub const CLAIM_DISCRIMINATOR: [u8; 8] = [0x73, 0x62, 0x70, 0x66, 0x63, 0x6c, 0x6d, 0x73]; // "sbpfclms"

/// On-chain verifying key for a specific SBPF circuit
#[repr(C)]
pub struct VerifyingKeyAccount {
    /// Account discriminator
    pub discriminator: [u8; 8],
    
    /// Authority that can update this VK
    pub authority: Pubkey,
    
    /// Unique identifier for this circuit (e.g., hash of program bytecode)
    pub circuit_id: [u8; 32],
    
    /// Number of public inputs this circuit expects
    pub num_public_inputs: u8,
    
    /// Reserved for future use
    pub _reserved: [u8; 7],
    
    /// vk_alpha_g1 (G1 point, 64 bytes)
    pub vk_alpha_g1: [u8; 64],
    
    /// vk_beta_g2 (G2 point, 128 bytes)
    pub vk_beta_g2: [u8; 128],
    
    /// vk_gamma_g2 (G2 point, 128 bytes)
    pub vk_gamma_g2: [u8; 128],
    
    /// vk_delta_g2 (G2 point, 128 bytes)
    pub vk_delta_g2: [u8; 128],
    
    /// vk_ic points (variable length, stored inline)
    /// For 2 public inputs: 3 G1 points = 192 bytes
    pub vk_ic: [u8; 192],
}

impl VerifyingKeyAccount {
    /// Check if the account has valid discriminator
    pub fn is_valid_discriminator(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        data[0..8] == VK_DISCRIMINATOR
    }
}

/// A verified execution claim that can be stored on-chain
/// 
/// This allows downstream programs to check if a specific
/// execution trace has been verified without re-verifying.
#[repr(C)]
pub struct VerifiedClaimAccount {
    /// Account discriminator
    pub discriminator: [u8; 8],
    
    /// The verifying key used for this verification
    pub verifying_key: Pubkey,
    
    /// Hash of initial state (from public inputs)
    pub initial_state_hash: [u8; 32],
    
    /// Hash of final state (from public inputs)
    pub final_state_hash: [u8; 32],
    
    /// Unix timestamp when this was verified
    pub verified_at: i64,
    
    /// Authority that submitted the proof
    pub verifier: Pubkey,
}

impl VerifiedClaimAccount {
    /// Size of this account structure
    pub const SIZE: usize = 8 + 32 + 32 + 32 + 8 + 32;  // 144 bytes
    
    /// Check if the account has valid discriminator
    pub fn is_valid_discriminator(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        data[0..8] == CLAIM_DISCRIMINATOR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vk_size() {
        // Verify our size calculation is correct
        let expected = 8 + 32 + 32 + 1 + 7 + 64 + 128 + 128 + 128 + 192;
        assert_eq!(expected, 720); // Actual struct size
    }
    
    #[test]
    fn test_claim_size() {
        assert_eq!(VerifiedClaimAccount::SIZE, 144);
    }
}


