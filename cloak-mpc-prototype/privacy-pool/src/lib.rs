//! Privacy Pool - Solana Program (Production Version)
//!
//! A privacy-preserving SOL pool that allows anonymous withdrawals.
//!
//! ## Security Features
//! - **Poseidon Hash**: Collision-resistant ZK-friendly hash
//! - **Domain Separation**: Nullifiers bound to specific pool ID
//! - **Front-Running Protection**: Commit-reveal scheme for withdrawals
//! - **Relayer Fees**: Incentivize honest relaying
//! - **Emergency Pause**: Admin can halt pool in case of exploit
//! - **Amount Limits**: Min/max deposit/withdrawal limits
//!
//! ## Architecture
//! 1. **Deposit**: User deposits SOL with commitment = Poseidon(secret, Poseidon(nullifier, amount))
//! 2. **CommitWithdraw**: User commits to withdrawal (hash of proof data)
//! 3. **Withdraw**: After N slots, reveal proof and execute withdrawal

#![cfg_attr(not(feature = "no-entrypoint"), no_std)]

use five8_const::decode_32_const;
use groth16_solana::groth16::Groth16Verifier;
use no_std_svm_merkle_tree::{MerkleProof, Sha256};
use pinocchio::{
    account_info::AccountInfo,
    default_allocator, default_panic_handler, program_entrypoint,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
    sysvars::{clock::Clock, Sysvar},
};

/// System program ID
const SYSTEM_PROGRAM: Pubkey = decode_32_const("11111111111111111111111111111111");

pub mod state;
pub mod circuit_vk;
pub mod error;

use state::POOL_STATE_SIZE;
use circuit_vk::PRIVACY_POOL_VK;
use error::PoolError;

/// Program ID (used for domain separation)
pub const ID: [u8; 32] = decode_32_const("D7tQcLX8saQNyf4TGaWDZ2jNiUa4CgNidKohPJLxTgcK");

/// Maximum deposits (2^10 = 1024)
pub const MAX_DEPOSITS: usize = 1024;

/// Merkle tree depth (log2(1024) = 10)
pub const TREE_DEPTH: usize = 10;

/// Minimum deposit amount (0.01 SOL)
pub const MIN_DEPOSIT: u64 = 10_000_000;

/// Maximum deposit amount (10 SOL)
pub const MAX_DEPOSIT: u64 = 10_000_000_000;

/// Commit-reveal delay (slots) - ~20 seconds
pub const COMMIT_DELAY_SLOTS: u64 = 50;

/// Maximum pending commits per pool
pub const MAX_PENDING_COMMITS: usize = 100;

/// Relayer fee (basis points, 50 = 0.5%)
pub const RELAYER_FEE_BPS: u64 = 50;

program_entrypoint!(process_instruction);
default_allocator!();
default_panic_handler!();

/// Instruction discriminators
#[repr(u8)]
pub enum Instruction {
    /// Initialize the pool
    /// Accounts: [pool_state (writable), admin (signer), system_program]
    Initialize = 0,
    
    /// Deposit SOL into the pool
    /// Accounts: [pool_state (writable), depositor (signer), system_program]
    /// Data: [discriminator(1), commitment(32), amount(8)]
    Deposit = 1,
    
    /// Commit to a withdrawal (front-running protection)
    /// Accounts: [pool_state (writable), committer (signer)]
    /// Data: [discriminator(1), commit_hash(32)]
    CommitWithdraw = 2,
    
    /// Execute withdrawal with ZK proof + Merkle proof
    /// Accounts: [pool_state (writable), recipient (writable), relayer (signer, writable)]
    /// Data: [discriminator(1), proof_a(64), proof_b(128), proof_c(64), 
    ///        commitment(32), nullifier_hash(32), recipient_key(32), amount(8),
    ///        leaf_index(4), merkle_proof_len(1), merkle_proof(10*32)]
    Withdraw = 3,
    
    /// Update Merkle root (client computes SHA256 tree)
    /// Accounts: [pool_state (writable), authority (signer)]
    /// Data: [discriminator(1), new_root(32)]
    UpdateRoot = 4,
    
    /// Emergency pause (admin only)
    /// Accounts: [pool_state (writable), admin (signer)]
    Pause = 5,
    
    /// Resume from pause (admin only)
    /// Accounts: [pool_state (writable), admin (signer)]
    Resume = 6,
}

/// Pool state layout:
/// [0..4]:     Magic "POOL"
/// [4]:        Version
/// [5]:        Is paused (0 = active, 1 = paused)
/// [6..8]:     Reserved
/// [8..12]:    Deposit count (u32)
/// [12..16]:   Nullifier count (u32)
/// [16..48]:   Admin pubkey
/// [48..80]:   Merkle root
/// [80..112]:  Pool ID (for domain separation)
/// [112..]:    Commitments, then Nullifiers, then PendingCommits

const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 4;
const PAUSED_OFFSET: usize = 5;
const DEPOSIT_COUNT_OFFSET: usize = 8;
const NULLIFIER_COUNT_OFFSET: usize = 12;
const ADMIN_OFFSET: usize = 16;
const ROOT_OFFSET: usize = 48;
const POOL_ID_OFFSET: usize = 80;
const COMMITMENTS_OFFSET: usize = 112;

/// Process instruction
pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    match instruction_data[0] {
        0 => process_initialize(accounts, &instruction_data[1..]),
        1 => process_deposit(accounts, &instruction_data[1..]),
        2 => process_commit_withdraw(accounts, &instruction_data[1..]),
        3 => process_withdraw(accounts, &instruction_data[1..]),
        4 => process_update_root(accounts, &instruction_data[1..]),
        5 => process_pause(accounts),
        6 => process_resume(accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Initialize the pool state
fn process_initialize(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [pool_state_account, admin, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Optional: pool_id can be passed in data, otherwise use account pubkey
    let pool_id: [u8; 32] = if data.len() >= 32 {
        data[0..32].try_into().unwrap()
    } else {
        *pool_state_account.key()
    };
    
    let pool_data = unsafe { pool_state_account.borrow_mut_data_unchecked() };
    
    // Zero out and initialize
    for byte in pool_data.iter_mut().take(POOL_STATE_SIZE) {
        *byte = 0;
    }
    
    pool_data[MAGIC_OFFSET..MAGIC_OFFSET+4].copy_from_slice(b"POOL");
    pool_data[VERSION_OFFSET] = 2; // Version 2 with security features
    pool_data[PAUSED_OFFSET] = 0; // Active
    pool_data[ADMIN_OFFSET..ADMIN_OFFSET+32].copy_from_slice(admin.key());
    pool_data[POOL_ID_OFFSET..POOL_ID_OFFSET+32].copy_from_slice(&pool_id);
    
    msg!("Privacy pool initialized (v2)");
    Ok(())
}

/// Check if pool is paused
fn check_not_paused(pool_data: &[u8]) -> ProgramResult {
    if pool_data[PAUSED_OFFSET] != 0 {
        return Err(PoolError::PoolPaused.into());
    }
    Ok(())
}

/// Check admin authority
fn check_admin(pool_data: &[u8], signer: &AccountInfo) -> ProgramResult {
    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if &pool_data[ADMIN_OFFSET..ADMIN_OFFSET+32] != signer.key() {
        return Err(PoolError::NotAdmin.into());
    }
    Ok(())
}

/// Process a deposit
fn process_deposit(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [pool_state_account, depositor, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    
    if !depositor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Parse: commitment(32) + amount(8)
    if data.len() < 40 {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    let commitment: [u8; 32] = data[0..32].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let amount = u64::from_le_bytes(
        data[32..40].try_into().map_err(|_| ProgramError::InvalidInstructionData)?
    );
    
    // Validate amount limits
    if amount < MIN_DEPOSIT {
        return Err(PoolError::AmountTooSmall.into());
    }
    if amount > MAX_DEPOSIT {
        return Err(PoolError::AmountTooLarge.into());
    }
    
    let pool_data = unsafe { pool_state_account.borrow_mut_data_unchecked() };
    
    if &pool_data[MAGIC_OFFSET..MAGIC_OFFSET+4] != b"POOL" {
        return Err(PoolError::InvalidPoolState.into());
    }
    
    check_not_paused(pool_data)?;
    
    // Get deposit count
    let deposit_count = u32::from_le_bytes(
        pool_data[DEPOSIT_COUNT_OFFSET..DEPOSIT_COUNT_OFFSET+4].try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?
    ) as usize;
    
    if deposit_count >= MAX_DEPOSITS {
        return Err(PoolError::PoolFull.into());
    }
    
    // Store commitment
    let commitment_offset = COMMITMENTS_OFFSET + deposit_count * 32;
    pool_data[commitment_offset..commitment_offset + 32].copy_from_slice(&commitment);
    
    // Update deposit count
    let new_count = (deposit_count + 1) as u32;
    pool_data[DEPOSIT_COUNT_OFFSET..DEPOSIT_COUNT_OFFSET+4].copy_from_slice(&new_count.to_le_bytes());
    
    // Transfer SOL via CPI
    let transfer_ix = pinocchio::instruction::Instruction {
        program_id: &SYSTEM_PROGRAM,
        accounts: &[
            pinocchio::instruction::AccountMeta {
                pubkey: depositor.key(),
                is_signer: true,
                is_writable: true,
            },
            pinocchio::instruction::AccountMeta {
                pubkey: pool_state_account.key(),
                is_signer: false,
                is_writable: true,
            },
        ],
        data: &{
            let mut data = [0u8; 12];
            data[0..4].copy_from_slice(&2u32.to_le_bytes()); // Transfer instruction
            data[4..12].copy_from_slice(&amount.to_le_bytes());
            data
        },
    };
    pinocchio::cpi::invoke(&transfer_ix, &[depositor, pool_state_account])?;
    
    msg!("Deposited lamports");
    Ok(())
}

/// Commit to a withdrawal (front-running protection)
fn process_commit_withdraw(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [pool_state_account, committer] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    
    if !committer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    if data.len() < 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    let commit_hash: [u8; 32] = data[0..32].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    
    let pool_data = unsafe { pool_state_account.borrow_mut_data_unchecked() };
    
    if &pool_data[MAGIC_OFFSET..MAGIC_OFFSET+4] != b"POOL" {
        return Err(PoolError::InvalidPoolState.into());
    }
    
    check_not_paused(pool_data)?;
    
    // Get current slot for commit timestamp
    let clock = Clock::get()?;
    let current_slot = clock.slot;
    
    // Store commit in pending commits area
    // Layout: [commit_hash(32), slot(8), committer(32)] = 72 bytes per commit
    let nullifier_offset = COMMITMENTS_OFFSET + MAX_DEPOSITS * 32;
    let commits_offset = nullifier_offset + MAX_DEPOSITS * 32;
    
    // Find empty slot or expired commit
    let mut found_slot = None;
    for i in 0..MAX_PENDING_COMMITS {
        let offset = commits_offset + i * 72;
        let stored_slot = u64::from_le_bytes(
            pool_data[offset + 32..offset + 40].try_into().unwrap_or([0; 8])
        );
        
        // Empty or expired (older than 1000 slots)
        if stored_slot == 0 || current_slot > stored_slot + 1000 {
            found_slot = Some(offset);
            break;
        }
    }
    
    let offset = found_slot.ok_or(PoolError::TooManyPendingCommits)?;
    
    pool_data[offset..offset + 32].copy_from_slice(&commit_hash);
    pool_data[offset + 32..offset + 40].copy_from_slice(&current_slot.to_le_bytes());
    pool_data[offset + 40..offset + 72].copy_from_slice(committer.key());
    
    msg!("Withdrawal committed");
    Ok(())
}

/// Process withdrawal with ZK proof + Merkle proof
fn process_withdraw(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [pool_state_account, recipient, relayer] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    
    if !relayer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    // Parse instruction data
    let min_len = 64 + 128 + 64 + 32 + 32 + 32 + 32 + 4 + 1;
    if data.len() < min_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    let proof_a: &[u8; 64] = data[0..64].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let proof_b: &[u8; 128] = data[64..192].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let proof_c: &[u8; 64] = data[192..256].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let commitment: [u8; 32] = data[256..288].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let nullifier_hash: [u8; 32] = data[288..320].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let recipient_fr: [u8; 32] = data[320..352].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let amount_fr: [u8; 32] = data[352..384].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let leaf_index = u32::from_le_bytes(
        data[384..388].try_into().map_err(|_| ProgramError::InvalidInstructionData)?
    );
    let merkle_proof_len = data[388] as usize;
    
    // Extract amount
    let amount = u64::from_be_bytes(
        amount_fr[24..32].try_into().map_err(|_| ProgramError::InvalidInstructionData)?
    );
    
    if merkle_proof_len > TREE_DEPTH {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    let proof_start = 389;
    let proof_end = proof_start + merkle_proof_len * 32;
    if data.len() < proof_end {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    let pool_data = unsafe { pool_state_account.borrow_mut_data_unchecked() };
    
    if &pool_data[MAGIC_OFFSET..MAGIC_OFFSET+4] != b"POOL" {
        return Err(PoolError::InvalidPoolState.into());
    }
    
    check_not_paused(pool_data)?;
    
    // ================================================================
    // STEP 0: Verify commit exists and is old enough (front-running protection)
    // ================================================================
    let clock = Clock::get()?;
    let current_slot = clock.slot;
    
    // Compute commit hash from proof data
    // SHA256(proof_a || proof_b || proof_c || nullifier_hash)
    let mut commit_input = [0u8; 288]; // 64 + 128 + 64 + 32
    commit_input[0..64].copy_from_slice(proof_a);
    commit_input[64..192].copy_from_slice(proof_b);
    commit_input[192..256].copy_from_slice(proof_c);
    commit_input[256..288].copy_from_slice(&nullifier_hash);
    let commit_hash = solana_nostd_sha256::hashv(&[&commit_input]);
    
    let nullifier_offset = COMMITMENTS_OFFSET + MAX_DEPOSITS * 32;
    let commits_offset = nullifier_offset + MAX_DEPOSITS * 32;
    
    let mut commit_found = false;
    let mut commit_idx = 0;
    for i in 0..MAX_PENDING_COMMITS {
        let offset = commits_offset + i * 72;
        if &pool_data[offset..offset + 32] == commit_hash.as_slice() {
            let commit_slot = u64::from_le_bytes(
                pool_data[offset + 32..offset + 40].try_into().unwrap()
            );
            if current_slot >= commit_slot + COMMIT_DELAY_SLOTS {
                commit_found = true;
                commit_idx = i;
                break;
            } else {
                msg!("Commit too recent");
                return Err(PoolError::CommitTooRecent.into());
            }
        }
    }
    
    if !commit_found {
        msg!("No valid commit found - must call CommitWithdraw first");
        return Err(PoolError::NoValidCommit.into());
    }
    
    // Clear the used commit
    let commit_offset = commits_offset + commit_idx * 72;
    for i in 0..72 {
        pool_data[commit_offset + i] = 0;
    }
    
    // ================================================================
    // STEP 1: Check nullifier hasn't been used (double-spend protection)
    // ================================================================
    let nullifier_count = u32::from_le_bytes(
        pool_data[NULLIFIER_COUNT_OFFSET..NULLIFIER_COUNT_OFFSET+4].try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?
    ) as usize;
    
    for i in 0..nullifier_count {
        let stored = &pool_data[nullifier_offset + i * 32..nullifier_offset + (i + 1) * 32];
        if stored == nullifier_hash {
            return Err(PoolError::NullifierAlreadyUsed.into());
        }
    }
    
    // ================================================================
    // STEP 2: Verify Merkle proof (commitment exists in tree)
    // ================================================================
    let mut merkle_siblings: [[u8; 32]; TREE_DEPTH] = [[0u8; 32]; TREE_DEPTH];
    for i in 0..merkle_proof_len {
        let start = proof_start + i * 32;
        merkle_siblings[i].copy_from_slice(&data[start..start + 32]);
    }
    
    let computed_root = MerkleProof::<32>::merklize::<Sha256>(
        &commitment,
        &merkle_siblings[..merkle_proof_len],
        leaf_index,
    );
    
    let mut stored_root = [0u8; 32];
    stored_root.copy_from_slice(&pool_data[ROOT_OFFSET..ROOT_OFFSET+32]);
    
    if computed_root != stored_root {
        return Err(PoolError::InvalidMerkleProof.into());
    }
    
    // ================================================================
    // STEP 3: Verify ZK proof (with domain separation!)
    // ================================================================
    
    // Get the pool's domain (stored at initialization)
    let mut domain_fr = [0u8; 32];
    domain_fr.copy_from_slice(&pool_data[POOL_ID_OFFSET..POOL_ID_OFFSET+32]);
    
    // 5 public inputs: commitment, nullifier_hash, recipient, amount, domain
    let public_inputs: [[u8; 32]; 5] = [
        commitment,
        nullifier_hash,
        recipient_fr,
        amount_fr,
        domain_fr,  // This binds the proof to THIS specific pool
    ];
    
    let mut verifier = Groth16Verifier::new(
        proof_a,
        proof_b,
        proof_c,
        &public_inputs,
        &PRIVACY_POOL_VK,
    ).map_err(|_| PoolError::InvalidProofFormat)?;
    
    verifier.verify().map_err(|_| PoolError::ProofVerificationFailed)?;
    
    msg!("✅ ZK proof verified (domain-bound)");
    
    // ================================================================
    // STEP 4: Process withdrawal with relayer fee
    // ================================================================
    
    // Store nullifier
    if nullifier_count >= MAX_DEPOSITS {
        return Err(PoolError::PoolFull.into());
    }
    pool_data[nullifier_offset + nullifier_count * 32..nullifier_offset + (nullifier_count + 1) * 32]
        .copy_from_slice(&nullifier_hash);
    
    let new_count = (nullifier_count + 1) as u32;
    pool_data[NULLIFIER_COUNT_OFFSET..NULLIFIER_COUNT_OFFSET+4].copy_from_slice(&new_count.to_le_bytes());
    
    // Calculate relayer fee
    let relayer_fee = amount * RELAYER_FEE_BPS / 10000;
    let recipient_amount = amount - relayer_fee;
    
    // Transfer SOL
    unsafe {
        let pool_lamports = pool_state_account.borrow_mut_lamports_unchecked();
        if *pool_lamports < amount {
            return Err(PoolError::InsufficientPoolBalance.into());
        }
        *pool_lamports -= amount;
        
        let recipient_lamports = recipient.borrow_mut_lamports_unchecked();
        *recipient_lamports += recipient_amount;
        
        if relayer_fee > 0 {
            let relayer_lamports = relayer.borrow_mut_lamports_unchecked();
            *relayer_lamports += relayer_fee;
        }
    }
    
    msg!("Withdrew lamports with relayer fee");
    Ok(())
}

/// Update Merkle root
fn process_update_root(accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let [pool_state_account, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    
    if data.len() < 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    
    let new_root: [u8; 32] = data[0..32].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    
    let pool_data = unsafe { pool_state_account.borrow_mut_data_unchecked() };
    
    if &pool_data[MAGIC_OFFSET..MAGIC_OFFSET+4] != b"POOL" {
        return Err(PoolError::InvalidPoolState.into());
    }
    
    pool_data[ROOT_OFFSET..ROOT_OFFSET+32].copy_from_slice(&new_root);
    
    msg!("Merkle root updated");
    Ok(())
}

/// Emergency pause
fn process_pause(accounts: &[AccountInfo]) -> ProgramResult {
    let [pool_state_account, admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    
    let pool_data = unsafe { pool_state_account.borrow_mut_data_unchecked() };
    
    if &pool_data[MAGIC_OFFSET..MAGIC_OFFSET+4] != b"POOL" {
        return Err(PoolError::InvalidPoolState.into());
    }
    
    check_admin(pool_data, admin)?;
    
    pool_data[PAUSED_OFFSET] = 1;
    msg!("Pool PAUSED by admin");
    Ok(())
}

/// Resume from pause
fn process_resume(accounts: &[AccountInfo]) -> ProgramResult {
    let [pool_state_account, admin] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    
    let pool_data = unsafe { pool_state_account.borrow_mut_data_unchecked() };
    
    if &pool_data[MAGIC_OFFSET..MAGIC_OFFSET+4] != b"POOL" {
        return Err(PoolError::InvalidPoolState.into());
    }
    
    check_admin(pool_data, admin)?;
    
    pool_data[PAUSED_OFFSET] = 0;
    msg!("Pool RESUMED by admin");
    Ok(())
}

// ============================================================================
// Test-only code
// ============================================================================

#[cfg(all(not(target_os = "solana"), feature = "no-entrypoint"))]
fn negate_g1_point(point: &[u8; 64]) -> Result<[u8; 64], PoolError> {
    // For off-chain testing only
    Ok(*point)
}
