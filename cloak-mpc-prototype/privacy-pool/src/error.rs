//! Error types for the Privacy Pool

use pinocchio::program_error::ProgramError;

/// Privacy pool errors
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PoolError {
    /// Pool state is invalid
    InvalidPoolState = 0,
    /// Pool is full (max deposits reached)
    PoolFull = 1,
    /// Nullifier has already been used (double-spend attempt)
    NullifierAlreadyUsed = 2,
    /// Proof verification failed
    ProofVerificationFailed = 3,
    /// Invalid proof format
    InvalidProofFormat = 4,
    /// Insufficient funds in depositor account
    InsufficientFunds = 5,
    /// Insufficient balance in pool
    InsufficientPoolBalance = 6,
    /// Recipient doesn't match proof
    RecipientMismatch = 7,
    /// Amount is too small
    AmountTooSmall = 8,
    /// Arithmetic overflow
    Overflow = 9,
    /// Invalid Merkle proof
    InvalidMerkleProof = 10,
    /// Amount exceeds maximum allowed
    AmountTooLarge = 11,
    /// Pool is paused by admin
    PoolPaused = 12,
    /// Caller is not the admin
    NotAdmin = 13,
    /// Commit is too recent (must wait for delay)
    CommitTooRecent = 14,
    /// No valid commit found (must call CommitWithdraw first)
    NoValidCommit = 15,
    /// Too many pending commits
    TooManyPendingCommits = 16,
}

impl From<PoolError> for ProgramError {
    fn from(e: PoolError) -> Self {
        ProgramError::Custom(7000 + e as u32)
    }
}

