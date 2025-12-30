//! Pool state account layout
//!
//! ```text
//! Offset  Size    Description
//! ------  ----    -----------
//! 0       4       Magic bytes "POOL"
//! 4       4       Version (u32)
//! 8       4       Deposit count (u32)
//! 12      4       Nullifier count (u32)  
//! 16      8       Total deposited (u64)
//! 24      8       Total withdrawn (u64)
//! 32      32      Reserved
//! 64      32*1024 Commitments (32 bytes each, up to 1024)
//! 32832   32*1024 Nullifiers (32 bytes each, up to 1024)
//! ```

use borsh::{BorshDeserialize, BorshSerialize};

/// Maximum deposits in the pool
pub const MAX_DEPOSITS: usize = 1024;

/// Size of the pool state account
pub const POOL_STATE_SIZE: usize = 64 + 32 * MAX_DEPOSITS * 2; // ~65KB

/// Pool state header (first 64 bytes)
#[derive(BorshSerialize, BorshDeserialize, Default, Clone)]
pub struct PoolState {
    /// Magic bytes: "POOL"
    pub magic: [u8; 4],
    /// Version
    pub version: u32,
    /// Number of deposits
    pub deposit_count: u32,
    /// Number of used nullifiers
    pub nullifier_count: u32,
    /// Total lamports deposited
    pub total_deposited: u64,
    /// Total lamports withdrawn
    pub total_withdrawn: u64,
    /// Reserved for future use
    pub reserved: [u8; 32],
}

impl PoolState {
    /// Check if the state is initialized
    pub fn is_initialized(&self) -> bool {
        self.magic == *b"POOL"
    }
}

/// A single deposit commitment
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Default)]
pub struct Commitment {
    pub data: [u8; 32],
}

/// A spent nullifier
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Default)]
pub struct Nullifier {
    pub hash: [u8; 32],
}


