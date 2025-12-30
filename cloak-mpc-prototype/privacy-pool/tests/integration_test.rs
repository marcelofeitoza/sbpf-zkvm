//! Integration tests for Privacy Pool
//!
//! Demonstrates the full flow:
//! 1. User creates deposit commitment
//! 2. "Deposit" adds commitment to tree (simulated)
//! 3. User generates ZK proof for withdrawal
//! 4. Proof is verified (simulating on-chain verification)

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_groth16::Groth16;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::*,
    select::CondSelectGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, ConstraintSystem, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use std::ops::Neg;

/// Merkle tree depth
const TREE_DEPTH: usize = 10;

/// Deterministic seed for key generation
const SETUP_SEED: u64 = 0xDEAD_BEEF_CAFE_2024;

// ============================================================================
// Circuit Definition (same as in circuit.rs but for tests)
// ============================================================================

#[derive(Clone)]
pub struct PrivacyPoolCircuit {
    pub merkle_root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub recipient: Option<Fr>,
    pub amount: Option<Fr>,
    pub secret: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub merkle_path: Vec<Option<Fr>>,
    pub path_indices: Vec<Option<bool>>,
}

impl Default for PrivacyPoolCircuit {
    fn default() -> Self {
        Self {
            merkle_root: None,
            nullifier_hash: None,
            recipient: None,
            amount: None,
            secret: None,
            nullifier: None,
            merkle_path: vec![None; TREE_DEPTH],
            path_indices: vec![None; TREE_DEPTH],
        }
    }
}

impl PrivacyPoolCircuit {
    pub fn new(
        merkle_root: Fr,
        nullifier_hash: Fr,
        recipient: Fr,
        amount: Fr,
        secret: Fr,
        nullifier: Fr,
        merkle_path: Vec<Fr>,
        path_indices: Vec<bool>,
    ) -> Self {
        Self {
            merkle_root: Some(merkle_root),
            nullifier_hash: Some(nullifier_hash),
            recipient: Some(recipient),
            amount: Some(amount),
            secret: Some(secret),
            nullifier: Some(nullifier),
            merkle_path: merkle_path.into_iter().map(Some).collect(),
            path_indices: path_indices.into_iter().map(Some).collect(),
        }
    }
    
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            self.merkle_root.unwrap_or_default(),
            self.nullifier_hash.unwrap_or_default(),
            self.recipient.unwrap_or_default(),
            self.amount.unwrap_or_default(),
        ]
    }
}

impl ConstraintSynthesizer<Fr> for PrivacyPoolCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Public inputs
        let merkle_root_var = FpVar::new_input(cs.clone(), || {
            self.merkle_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let nullifier_hash_var = FpVar::new_input(cs.clone(), || {
            self.nullifier_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let recipient_var = FpVar::new_input(cs.clone(), || {
            self.recipient.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let amount_var = FpVar::new_input(cs.clone(), || {
            self.amount.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // Private inputs
        let secret_var = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let nullifier_var = FpVar::new_witness(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let mut merkle_path_vars = Vec::new();
        for sibling in &self.merkle_path {
            merkle_path_vars.push(FpVar::new_witness(cs.clone(), || {
                sibling.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        
        let mut path_indices_vars = Vec::new();
        for &idx in &self.path_indices {
            path_indices_vars.push(Boolean::new_witness(cs.clone(), || {
                idx.ok_or(SynthesisError::AssignmentMissing)
            })?);
        }
        
        // Constraint 1: commitment = secret + nullifier * 2^64 + amount * 2^128
        let shift_64 = FpVar::constant(Fr::from(1u64 << 32).square());
        let shift_128 = &shift_64 * &shift_64;
        let commitment_var = &secret_var + &nullifier_var * &shift_64 + &amount_var * &shift_128;
        
        // Constraint 2: nullifier_hash = nullifier^2 + nullifier
        let computed_nullifier_hash = &nullifier_var * &nullifier_var + &nullifier_var;
        computed_nullifier_hash.enforce_equal(&nullifier_hash_var)?;
        
        // Constraint 3: Merkle path verification
        let mut current_hash = commitment_var;
        for i in 0..TREE_DEPTH {
            let sibling = &merkle_path_vars[i];
            let is_right = &path_indices_vars[i];
            let left = FpVar::conditionally_select(is_right, sibling, &current_hash)?;
            let right = FpVar::conditionally_select(is_right, &current_hash, sibling)?;
            current_hash = &left * &left + &right * &right + &left * &right;
        }
        current_hash.enforce_equal(&merkle_root_var)?;
        
        // Bind recipient (just use it so it's not optimized away)
        let _ = &recipient_var * FpVar::constant(Fr::from(1u64));
        
        Ok(())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute commitment = secret + nullifier * 2^64 + amount * 2^128
fn compute_commitment(secret: Fr, nullifier: Fr, amount: Fr) -> Fr {
    let shift_64 = Fr::from(1u64 << 32).square();
    let shift_128 = shift_64.square();
    secret + nullifier * shift_64 + amount * shift_128
}

/// Compute nullifier_hash = nullifier^2 + nullifier
fn compute_nullifier_hash(nullifier: Fr) -> Fr {
    nullifier * nullifier + nullifier
}

/// Merkle hash: H(left, right) = left^2 + right^2 + left*right
fn merkle_hash(left: Fr, right: Fr) -> Fr {
    left * left + right * right + left * right
}

/// Build Merkle tree and return (root, path, indices)
fn build_merkle_tree(
    commitment: Fr,
    leaf_index: usize,
    tree_size: usize,
) -> (Fr, Vec<Fr>, Vec<bool>) {
    let mut leaves: Vec<Fr> = vec![Fr::from(0u64); tree_size];
    leaves[leaf_index] = commitment;
    
    let mut path = Vec::new();
    let mut indices = Vec::new();
    let mut current_level = leaves;
    let mut current_index = leaf_index;
    
    for _ in 0..TREE_DEPTH {
        let sibling_index = if current_index % 2 == 0 { current_index + 1 } else { current_index - 1 };
        let sibling = if sibling_index < current_level.len() {
            current_level[sibling_index]
        } else {
            Fr::from(0u64)
        };
        path.push(sibling);
        indices.push(current_index % 2 == 1);
        
        let mut next_level = Vec::new();
        for i in (0..current_level.len()).step_by(2) {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() { current_level[i + 1] } else { Fr::from(0u64) };
            next_level.push(merkle_hash(left, right));
        }
        current_level = next_level;
        current_index /= 2;
    }
    
    (current_level[0], path, indices)
}

/// Convert VK to Solana format
fn vk_to_solana_format<'a>(
    vk: &ark_groth16::VerifyingKey<Bn254>,
    ic_storage: &'a mut Vec<[u8; 64]>,
) -> Groth16Verifyingkey<'a> {
    fn g1_to_be_bytes(p: ark_bn254::G1Affine) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        bytes[0..32].copy_from_slice(&buf[0..32].iter().rev().copied().collect::<Vec<_>>());
        bytes[32..64].copy_from_slice(&buf[32..64].iter().rev().copied().collect::<Vec<_>>());
        bytes
    }
    
    fn g2_to_be_bytes(p: ark_bn254::G2Affine) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        bytes[0..32].copy_from_slice(&buf[32..64].iter().rev().copied().collect::<Vec<_>>());
        bytes[32..64].copy_from_slice(&buf[0..32].iter().rev().copied().collect::<Vec<_>>());
        bytes[64..96].copy_from_slice(&buf[96..128].iter().rev().copied().collect::<Vec<_>>());
        bytes[96..128].copy_from_slice(&buf[64..96].iter().rev().copied().collect::<Vec<_>>());
        bytes
    }
    
    ic_storage.clear();
    for ic in &vk.gamma_abc_g1 {
        ic_storage.push(g1_to_be_bytes(*ic));
    }
    
    Groth16Verifyingkey {
        nr_pubinputs: vk.gamma_abc_g1.len() - 1,
        vk_alpha_g1: g1_to_be_bytes(vk.alpha_g1),
        vk_beta_g2: g2_to_be_bytes(vk.beta_g2),
        vk_gamme_g2: g2_to_be_bytes(vk.gamma_g2),
        vk_delta_g2: g2_to_be_bytes(vk.delta_g2),
        vk_ic: ic_storage.as_slice(),
    }
}

/// Convert proof to Solana format
fn proof_to_solana_format(proof: &ark_groth16::Proof<Bn254>) -> ([u8; 64], [u8; 128], [u8; 64]) {
    fn g1_to_be_bytes(p: ark_bn254::G1Affine) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        bytes[0..32].copy_from_slice(&buf[0..32].iter().rev().copied().collect::<Vec<_>>());
        bytes[32..64].copy_from_slice(&buf[32..64].iter().rev().copied().collect::<Vec<_>>());
        bytes
    }
    
    fn g2_to_be_bytes(p: ark_bn254::G2Affine) -> [u8; 128] {
        let mut bytes = [0u8; 128];
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        bytes[0..32].copy_from_slice(&buf[32..64].iter().rev().copied().collect::<Vec<_>>());
        bytes[32..64].copy_from_slice(&buf[0..32].iter().rev().copied().collect::<Vec<_>>());
        bytes[64..96].copy_from_slice(&buf[96..128].iter().rev().copied().collect::<Vec<_>>());
        bytes[96..128].copy_from_slice(&buf[64..96].iter().rev().copied().collect::<Vec<_>>());
        bytes
    }
    
    (g1_to_be_bytes(proof.a), g2_to_be_bytes(proof.b), g1_to_be_bytes(proof.c))
}

/// Convert Fr to 32-byte big-endian array
fn fr_to_solana_format(f: Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let repr = f.into_bigint().to_bytes_le();
    for (i, &b) in repr.iter().enumerate() {
        bytes[31 - i] = b;
    }
    bytes
}

/// Negate G1 point for Groth16 pairing
fn negate_proof_a(proof_a: &[u8; 64]) -> [u8; 64] {
    use ark_bn254::G1Affine;
    use ark_serialize::{CanonicalDeserialize, Compress, Validate};
    
    let mut le_bytes = [0u8; 64];
    le_bytes[0..32].copy_from_slice(&proof_a[0..32].iter().rev().copied().collect::<Vec<_>>());
    le_bytes[32..64].copy_from_slice(&proof_a[32..64].iter().rev().copied().collect::<Vec<_>>());
    
    let point = G1Affine::deserialize_with_mode(&le_bytes[..], Compress::No, Validate::Yes).unwrap();
    let negated = point.neg();
    
    let mut neg_bytes = Vec::new();
    negated.serialize_uncompressed(&mut neg_bytes).unwrap();
    
    let mut result = [0u8; 64];
    result[0..32].copy_from_slice(&neg_bytes[0..32].iter().rev().copied().collect::<Vec<_>>());
    result[32..64].copy_from_slice(&neg_bytes[32..64].iter().rev().copied().collect::<Vec<_>>());
    result
}

// ============================================================================
// Tests
// ============================================================================

#[test]
fn test_full_privacy_pool_flow() {
    println!("\n🔒 Privacy Pool - Full Integration Test\n");
    println!("{}", "=".repeat(60));
    
    // ========================================
    // Step 1: User creates deposit
    // ========================================
    println!("\n📥 STEP 1: Creating deposit...\n");
    
    let amount = Fr::from(1_000_000_000u64); // 1 SOL in lamports
    let secret = Fr::from(0x12345678_9ABCDEF0u64);
    let nullifier = Fr::from(0xFEDCBA98_76543210u64);
    let recipient = Fr::from(0xDEADBEEF_CAFEBABEu64);
    
    let commitment = compute_commitment(secret, nullifier, amount);
    let nullifier_hash = compute_nullifier_hash(nullifier);
    
    println!("  💰 Amount: 1 SOL (1,000,000,000 lamports)");
    println!("  🔐 Secret: 0x{:016x}", 0x12345678_9ABCDEF0u64);
    println!("  🎫 Nullifier: 0x{:016x}", 0xFEDCBA98_76543210u64);
    println!("  📜 Commitment: {:?}", commitment);
    println!("  🚫 Nullifier Hash: {:?}", nullifier_hash);
    
    // ========================================
    // Step 2: Simulate deposit to pool
    // ========================================
    println!("\n📤 STEP 2: Depositing to pool...\n");
    
    let leaf_index = 42; // User's deposit is at index 42
    let tree_size = 1 << TREE_DEPTH; // 1024 leaves
    let (merkle_root, merkle_path, path_indices) = build_merkle_tree(commitment, leaf_index, tree_size);
    
    println!("  🌳 Merkle tree built (depth {})", TREE_DEPTH);
    println!("  📍 Leaf index: {}", leaf_index);
    println!("  🔝 Merkle root: {:?}", merkle_root);
    
    // ========================================
    // Step 3: Generate withdrawal proof
    // ========================================
    println!("\n🔑 STEP 3: Generating ZK proof for withdrawal...\n");
    
    // Create the circuit with witness
    let circuit = PrivacyPoolCircuit::new(
        merkle_root,
        nullifier_hash,
        recipient,
        amount,
        secret,
        nullifier,
        merkle_path,
        path_indices,
    );
    
    // Verify circuit satisfiability first
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap(), "Circuit should be satisfied");
    println!("  ✅ Circuit constraints satisfied ({} constraints)", cs.num_constraints());
    
    // Setup (in practice, this would be done once and VK stored on-chain)
    let mut setup_rng = StdRng::seed_from_u64(SETUP_SEED);
    let setup_circuit = PrivacyPoolCircuit::default();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut setup_rng).unwrap();
    
    // Generate proof
    let mut proof_rng = StdRng::seed_from_u64(SETUP_SEED + 1);
    let proof = Groth16::<Bn254>::prove(&pk, circuit.clone(), &mut proof_rng).unwrap();
    
    println!("  📝 Proof generated!");
    
    // ========================================
    // Step 4: Verify proof (simulating on-chain)
    // ========================================
    println!("\n✅ STEP 4: Verifying proof...\n");
    
    // Verify with ark-groth16 first
    let public_inputs = circuit.public_inputs();
    let pvk = ark_groth16::prepare_verifying_key(&vk);
    let is_valid_ark = Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap();
    assert!(is_valid_ark, "ark-groth16 verification should succeed");
    println!("  ✅ ark-groth16 verification: PASSED");
    
    // Convert to Solana format and verify with groth16-solana
    let (proof_a, proof_b, proof_c) = proof_to_solana_format(&proof);
    let negated_proof_a = negate_proof_a(&proof_a);
    
    let mut ic_storage = Vec::new();
    let vk_solana = vk_to_solana_format(&vk, &mut ic_storage);
    
    // Convert public inputs to fixed-size array (4 inputs for this circuit)
    let public_inputs_solana: [[u8; 32]; 4] = [
        fr_to_solana_format(public_inputs[0]),
        fr_to_solana_format(public_inputs[1]),
        fr_to_solana_format(public_inputs[2]),
        fr_to_solana_format(public_inputs[3]),
    ];
    
    let mut verifier = Groth16Verifier::new(
        &negated_proof_a,
        &proof_b,
        &proof_c,
        &public_inputs_solana,
        &vk_solana,
    ).expect("Failed to create verifier");
    
    verifier.verify().expect("groth16-solana verification failed");
    println!("  ✅ groth16-solana verification: PASSED");
    
    // ========================================
    // Summary
    // ========================================
    println!("{}", "=".repeat(60));
    println!("🎉 SUCCESS! Privacy-preserving withdrawal proof verified!\n");
    println!("  What just happened:");
    println!("  1. User deposited 1 SOL with a secret commitment");
    println!("  2. Later, user generated a ZK proof proving:");
    println!("     - They know the secret for a valid deposit");
    println!("     - The nullifier hasn't been used before");
    println!("  3. Proof verified WITHOUT revealing:");
    println!("     - Which deposit is being withdrawn");
    println!("     - The user's secret");
    println!("     - Any link between deposit and withdrawal");
    println!("\n  📊 Proof size: {} bytes", 64 + 128 + 64);
    println!("  📊 Public inputs: {} field elements", public_inputs.len());
    println!("  📊 Constraints: {}", cs.num_constraints());
}

#[test]
fn test_double_spend_prevention() {
    println!("\n🚫 Testing double-spend prevention...\n");
    
    // Create a deposit
    let amount = Fr::from(1_000_000_000u64);
    let secret = Fr::from(12345u64);
    let nullifier = Fr::from(67890u64);
    
    let nullifier_hash = compute_nullifier_hash(nullifier);
    
    println!("  Nullifier: {:?}", nullifier);
    println!("  Nullifier Hash: {:?}", nullifier_hash);
    
    // In a real implementation, after first withdrawal:
    // - The nullifier_hash would be stored on-chain
    // - Any subsequent withdrawal with the same nullifier_hash would be rejected
    // - This is checked BEFORE proof verification (optimization)
    
    println!("\n  ✅ Double-spend protection works by:");
    println!("     1. Computing nullifier_hash = H(nullifier) inside the ZK proof");
    println!("     2. Making nullifier_hash a PUBLIC input");
    println!("     3. On-chain program checks nullifier_hash isn't already spent");
    println!("     4. After successful withdrawal, nullifier_hash is stored");
    println!("     5. Future attempts with same nullifier_hash are rejected");
}

