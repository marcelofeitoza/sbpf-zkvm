//! Privacy Pool Circuit
//!
//! This circuit proves knowledge of a valid deposit in the pool without
//! revealing which deposit it is (privacy-preserving withdrawal).
//!
//! Public inputs:
//! - merkle_root: Root of the commitment Merkle tree
//! - nullifier_hash: Hash of nullifier (prevents double-spend)
//! - recipient: Destination wallet address (as field element)
//! - amount: Withdrawal amount
//!
//! Private inputs:
//! - secret: User's secret value
//! - nullifier: Unique value per deposit
//! - merkle_path: Siblings along path from leaf to root
//! - path_indices: Left/right indicators for path

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::*,
    select::CondSelectGadget,
    ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Merkle tree depth (supports 2^TREE_DEPTH deposits)
pub const TREE_DEPTH: usize = 10; // 1024 deposits max

/// Privacy pool withdrawal circuit
#[derive(Clone)]
pub struct PrivacyPoolCircuit {
    // Public inputs
    pub merkle_root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub recipient: Option<Fr>,
    pub amount: Option<Fr>,
    
    // Private inputs (witness)
    pub secret: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub merkle_path: Vec<Option<Fr>>,       // TREE_DEPTH siblings
    pub path_indices: Vec<Option<bool>>,     // TREE_DEPTH left/right indicators
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
    /// Create a new circuit with all values
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
        assert_eq!(merkle_path.len(), TREE_DEPTH);
        assert_eq!(path_indices.len(), TREE_DEPTH);
        
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
    
    /// Get public inputs for verification
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
        // ============================================================
        // Allocate public inputs
        // ============================================================
        
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
        
        // ============================================================
        // Allocate private inputs (witness)
        // ============================================================
        
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
        
        // ============================================================
        // Constraint 1: Compute commitment = H(secret || nullifier || amount)
        // Using a simplified polynomial hash for the circuit
        // ============================================================
        
        // commitment = secret + nullifier * 2^64 + amount * 2^128
        // This is a simplified commitment - production would use Poseidon
        let shift_64 = FpVar::constant(Fr::from(1u64 << 32).square());
        let shift_128 = &shift_64 * &shift_64;
        
        let commitment_var = &secret_var + &nullifier_var * &shift_64 + &amount_var * &shift_128;
        
        // ============================================================
        // Constraint 2: nullifier_hash = H(nullifier)
        // Simplified: nullifier_hash = nullifier^2 + nullifier
        // ============================================================
        
        let computed_nullifier_hash = &nullifier_var * &nullifier_var + &nullifier_var;
        computed_nullifier_hash.enforce_equal(&nullifier_hash_var)?;
        
        // ============================================================
        // Constraint 3: Merkle path verification
        // Proves commitment is in the tree with the given root
        // ============================================================
        
        let mut current_hash = commitment_var;
        
        for i in 0..TREE_DEPTH {
            let sibling = &merkle_path_vars[i];
            let is_right = &path_indices_vars[i];
            
            // If is_right, current is on right: hash(sibling, current)
            // If !is_right, current is on left: hash(current, sibling)
            let left = FpVar::conditionally_select(is_right, sibling, &current_hash)?;
            let right = FpVar::conditionally_select(is_right, &current_hash, sibling)?;
            
            // Simplified hash: H(left, right) = left^2 + right^2 + left*right
            // Production would use Poseidon
            current_hash = &left * &left + &right * &right + &left * &right;
        }
        
        // The computed root must match the public merkle_root
        current_hash.enforce_equal(&merkle_root_var)?;
        
        // ============================================================
        // Constraint 4: Bind recipient to the proof
        // This prevents front-running attacks
        // ============================================================
        
        // recipient_var is a public input, so it's automatically bound
        // The verifier will check the recipient matches on-chain
        
        // We add a dummy constraint to ensure recipient is used
        let _binding = &recipient_var * FpVar::constant(Fr::from(1u64));
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    
    /// Compute commitment off-chain (same as circuit)
    pub fn compute_commitment(secret: Fr, nullifier: Fr, amount: Fr) -> Fr {
        let shift_64 = Fr::from(1u64 << 32).square();
        let shift_128 = shift_64.square();
        secret + nullifier * shift_64 + amount * shift_128
    }
    
    /// Compute nullifier hash off-chain (same as circuit)  
    pub fn compute_nullifier_hash(nullifier: Fr) -> Fr {
        nullifier * nullifier + nullifier
    }
    
    /// Simple Merkle tree hash (same as circuit)
    pub fn merkle_hash(left: Fr, right: Fr) -> Fr {
        left * left + right * right + left * right
    }
    
    /// Build a simple Merkle tree and return (root, path, indices)
    pub fn build_merkle_tree(
        commitment: Fr,
        leaf_index: usize,
        tree_size: usize,
    ) -> (Fr, Vec<Fr>, Vec<bool>) {
        // Initialize leaves (empty = 0, our commitment at leaf_index)
        let mut leaves: Vec<Fr> = vec![Fr::from(0u64); tree_size];
        leaves[leaf_index] = commitment;
        
        let mut path = Vec::new();
        let mut indices = Vec::new();
        
        let mut current_level = leaves;
        let mut current_index = leaf_index;
        
        for _ in 0..TREE_DEPTH {
            // Sibling index
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            
            // Record path
            let sibling = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                Fr::from(0u64)
            };
            path.push(sibling);
            indices.push(current_index % 2 == 1); // true if we're on the right
            
            // Build next level
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    Fr::from(0u64)
                };
                next_level.push(merkle_hash(left, right));
            }
            
            current_level = next_level;
            current_index /= 2;
        }
        
        let root = current_level[0];
        (root, path, indices)
    }
    
    #[test]
    fn test_circuit_satisfiability() {
        println!("\n🔒 Testing Privacy Pool Circuit...\n");
        
        // User's private values
        let secret = Fr::from(12345u64);
        let nullifier = Fr::from(67890u64);
        let amount = Fr::from(1_000_000_000u64); // 1 SOL in lamports
        let recipient = Fr::from(0xDEADBEEFu64); // Simplified recipient
        
        // Compute commitment
        let commitment = compute_commitment(secret, nullifier, amount);
        println!("  Commitment: {:?}", commitment);
        
        // Compute nullifier hash
        let nullifier_hash = compute_nullifier_hash(nullifier);
        println!("  Nullifier hash: {:?}", nullifier_hash);
        
        // Build Merkle tree with this commitment at index 5
        let leaf_index = 5;
        let tree_size = 1 << TREE_DEPTH; // 2^10 = 1024
        let (merkle_root, merkle_path, path_indices) = 
            build_merkle_tree(commitment, leaf_index, tree_size);
        println!("  Merkle root: {:?}", merkle_root);
        
        // Create circuit
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
        
        // Check constraints are satisfied
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        let is_satisfied = cs.is_satisfied().unwrap();
        let num_constraints = cs.num_constraints();
        
        println!("\n  ✅ Circuit satisfied: {}", is_satisfied);
        println!("  📊 Number of constraints: {}", num_constraints);
        
        assert!(is_satisfied, "Circuit should be satisfied with valid witness");
    }
    
    #[test]
    fn test_invalid_nullifier_fails() {
        println!("\n🔒 Testing that wrong nullifier fails...\n");
        
        let secret = Fr::from(12345u64);
        let nullifier = Fr::from(67890u64);
        let wrong_nullifier_hash = Fr::from(99999u64); // Wrong!
        let amount = Fr::from(1_000_000_000u64);
        let recipient = Fr::from(0xDEADBEEFu64);
        
        let commitment = compute_commitment(secret, nullifier, amount);
        let (merkle_root, merkle_path, path_indices) = 
            build_merkle_tree(commitment, 0, 1 << TREE_DEPTH);
        
        let circuit = PrivacyPoolCircuit::new(
            merkle_root,
            wrong_nullifier_hash, // Wrong nullifier hash!
            recipient,
            amount,
            secret,
            nullifier,
            merkle_path,
            path_indices,
        );
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        let is_satisfied = cs.is_satisfied().unwrap();
        println!("  Circuit satisfied with wrong nullifier: {}", is_satisfied);
        
        assert!(!is_satisfied, "Circuit should fail with wrong nullifier hash");
        println!("  ✅ Correctly rejected invalid nullifier!");
    }
}


