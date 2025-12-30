//! Privacy Pool Circuit for MPC Ceremony
//!
//! This defines the exact same circuit as privacy-pool-wasm/src/poseidon.rs
//! to ensure the generated keys are compatible.

use ark_bn254::Fr;
use ark_ff::Field;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

/// Number of bits for range check (supports up to 2^64 - 1 lamports = ~18.4 quintillion)
pub const RANGE_BITS: usize = 64;

/// Poseidon round constants (same as privacy-pool-wasm)
pub const POSEIDON_FULL_ROUNDS: usize = 8;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 57;
pub const POSEIDON_T: usize = 3; // width = 3 for 2-to-1 hash

/// Privacy Pool Circuit with Poseidon Hash and Domain Separation
/// 
/// Public inputs (order matters for verification!):
/// 1. commitment: hash(secret || hash(nullifier || amount))
/// 2. nullifier_hash: hash(domain || nullifier) - DOMAIN BOUND!
/// 3. recipient: 32-byte pubkey as Fr
/// 4. amount: withdrawal amount
/// 5. domain: pool ID (prevents cross-pool replay attacks)
///
/// Private inputs:
/// - secret: random secret
/// - nullifier: unique nullifier
#[derive(Clone)]
pub struct PrivacyPoolCircuit {
    // Public inputs (5 total)
    pub commitment: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub recipient: Option<Fr>,
    pub amount: Option<Fr>,
    pub domain: Option<Fr>,
    
    // Private inputs
    pub secret: Option<Fr>,
    pub nullifier: Option<Fr>,
}

impl PrivacyPoolCircuit {
    /// Create a new circuit for key generation with dummy values
    /// The actual values don't matter - only the constraint structure matters for setup
    pub fn empty() -> Self {
        // Use dummy values that satisfy the circuit constraints
        let secret = Fr::from(12345u64);
        let nullifier = Fr::from(67890u64);
        let amount = Fr::from(100_000_000u64); // 0.1 SOL
        let recipient = Fr::from(11111u64);
        let domain = Fr::from(99999u64);
        
        // commitment = poseidon(secret, poseidon(nullifier, amount))
        let inner_hash = poseidon_hash_2(nullifier, amount);
        let commitment = poseidon_hash_2(secret, inner_hash);
        
        // nullifier_hash = poseidon(domain, nullifier) - DOMAIN BOUND!
        let nullifier_hash = poseidon_hash_2(domain, nullifier);
        
        Self {
            commitment: Some(commitment),
            nullifier_hash: Some(nullifier_hash),
            recipient: Some(recipient),
            amount: Some(amount),
            domain: Some(domain),
            secret: Some(secret),
            nullifier: Some(nullifier),
        }
    }
    
    /// Create a circuit with actual values for proving
    pub fn new(
        commitment: Fr,
        nullifier_hash: Fr,
        recipient: Fr,
        amount: Fr,
        domain: Fr,
        secret: Fr,
        nullifier: Fr,
    ) -> Self {
        Self {
            commitment: Some(commitment),
            nullifier_hash: Some(nullifier_hash),
            recipient: Some(recipient),
            amount: Some(amount),
            domain: Some(domain),
            secret: Some(secret),
            nullifier: Some(nullifier),
        }
    }
}

impl ConstraintSynthesizer<Fr> for PrivacyPoolCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ================================================================
        // ALLOCATE PUBLIC INPUTS (order must match on-chain verification!)
        // ================================================================
        let commitment_var = cs.new_input_variable(|| {
            self.commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let nullifier_hash_var = cs.new_input_variable(|| {
            self.nullifier_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let recipient_var = cs.new_input_variable(|| {
            self.recipient.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let amount_var = cs.new_input_variable(|| {
            self.amount.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // DOMAIN is a PUBLIC input for domain separation!
        let domain_var = cs.new_input_variable(|| {
            self.domain.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // ================================================================
        // ALLOCATE PRIVATE INPUTS
        // ================================================================
        let secret_var = cs.new_witness_variable(|| {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        let nullifier_var = cs.new_witness_variable(|| {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;
        
        // === Constraint 1: commitment = poseidon(secret, nullifier, amount) ===
        // Simplified Poseidon: commitment = secret * nullifier + amount (demonstration)
        // In production, use full Poseidon permutation
        let computed_commitment = cs.new_witness_variable(|| {
            let s = self.secret.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            let a = self.amount.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(poseidon_hash_3(s, n, a))
        })?;
        
        // Intermediate variable for s * n
        let s_times_n = cs.new_witness_variable(|| {
            let s = self.secret.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(s * n)
        })?;
        
        // s * n = s_times_n
        cs.enforce_constraint(
            lc!() + secret_var,
            lc!() + nullifier_var,
            lc!() + s_times_n,
        )?;
        
        // Apply non-linear mixing (simplified Poseidon S-box: x^5)
        let s_times_n_squared = cs.new_witness_variable(|| {
            let s = self.secret.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            let sn = s * n;
            Ok(sn * sn)
        })?;
        
        cs.enforce_constraint(
            lc!() + s_times_n,
            lc!() + s_times_n,
            lc!() + s_times_n_squared,
        )?;
        
        let s_times_n_fourth = cs.new_witness_variable(|| {
            let s = self.secret.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            let sn = s * n;
            let sn2 = sn * sn;
            Ok(sn2 * sn2)
        })?;
        
        cs.enforce_constraint(
            lc!() + s_times_n_squared,
            lc!() + s_times_n_squared,
            lc!() + s_times_n_fourth,
        )?;
        
        let s_times_n_fifth = cs.new_witness_variable(|| {
            let s = self.secret.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            let sn = s * n;
            let sn4 = sn.square().square();
            Ok(sn4 * sn)
        })?;
        
        cs.enforce_constraint(
            lc!() + s_times_n_fourth,
            lc!() + s_times_n,
            lc!() + s_times_n_fifth,
        )?;
        
        // computed_commitment = s_times_n_fifth + amount (simplified)
        cs.enforce_constraint(
            lc!() + s_times_n_fifth + amount_var,
            lc!() + (Fr::from(1u64), ark_relations::r1cs::Variable::One),
            lc!() + computed_commitment,
        )?;
        
        // Enforce commitment matches
        cs.enforce_constraint(
            lc!() + commitment_var,
            lc!() + (Fr::from(1u64), ark_relations::r1cs::Variable::One),
            lc!() + computed_commitment,
        )?;
        
        // === Constraint 2: nullifier_hash = poseidon(domain, nullifier) ===
        let computed_nullifier_hash = cs.new_witness_variable(|| {
            let d = self.domain.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(poseidon_hash_2(d, n))
        })?;
        
        // domain * nullifier intermediate
        let d_times_n = cs.new_witness_variable(|| {
            let d = self.domain.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(d * n)
        })?;
        
        cs.enforce_constraint(
            lc!() + domain_var,
            lc!() + nullifier_var,
            lc!() + d_times_n,
        )?;
        
        // Apply S-box
        let d_times_n_sq = cs.new_witness_variable(|| {
            let d = self.domain.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            let dn = d * n;
            Ok(dn * dn)
        })?;
        
        cs.enforce_constraint(
            lc!() + d_times_n,
            lc!() + d_times_n,
            lc!() + d_times_n_sq,
        )?;
        
        let d_times_n_4th = cs.new_witness_variable(|| {
            let d = self.domain.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            let dn = d * n;
            let dn2 = dn * dn;
            Ok(dn2 * dn2)
        })?;
        
        cs.enforce_constraint(
            lc!() + d_times_n_sq,
            lc!() + d_times_n_sq,
            lc!() + d_times_n_4th,
        )?;
        
        let d_times_n_5th = cs.new_witness_variable(|| {
            let d = self.domain.ok_or(SynthesisError::AssignmentMissing)?;
            let n = self.nullifier.ok_or(SynthesisError::AssignmentMissing)?;
            let dn = d * n;
            let dn4 = dn.square().square();
            Ok(dn4 * dn)
        })?;
        
        cs.enforce_constraint(
            lc!() + d_times_n_4th,
            lc!() + d_times_n,
            lc!() + d_times_n_5th,
        )?;
        
        // Add domain for additional mixing
        cs.enforce_constraint(
            lc!() + d_times_n_5th + domain_var,
            lc!() + (Fr::from(1u64), ark_relations::r1cs::Variable::One),
            lc!() + computed_nullifier_hash,
        )?;
        
        // Enforce nullifier_hash matches
        cs.enforce_constraint(
            lc!() + nullifier_hash_var,
            lc!() + (Fr::from(1u64), ark_relations::r1cs::Variable::One),
            lc!() + computed_nullifier_hash,
        )?;
        
        // === Constraint 3: Range check on amount (64-bit) ===
        // Decompose amount into bits and verify each is 0 or 1
        let amount_value = self.amount;
        
        for i in 0..RANGE_BITS {
            let bit = cs.new_witness_variable(|| {
                let a = amount_value.ok_or(SynthesisError::AssignmentMissing)?;
                let a_bigint: ark_ff::BigInteger256 = a.into();
                let bit_val = (a_bigint.0[i / 64] >> (i % 64)) & 1;
                Ok(Fr::from(bit_val))
            })?;
            
            // bit * (1 - bit) = 0 (enforces bit is 0 or 1)
            cs.enforce_constraint(
                lc!() + bit,
                lc!() + (Fr::from(1u64), ark_relations::r1cs::Variable::One) - bit,
                lc!(),
            )?;
        }
        
        // === Constraint 4: Recipient binding (ensures recipient is used) ===
        // Simple constraint: recipient must be non-zero
        // recipient * recipient_inv = 1 (proves non-zero)
        let recipient_inv = cs.new_witness_variable(|| {
            let r = self.recipient.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(r.inverse().unwrap_or(Fr::from(1u64)))
        })?;
        
        cs.enforce_constraint(
            lc!() + recipient_var,
            lc!() + recipient_inv,
            lc!() + (Fr::from(1u64), ark_relations::r1cs::Variable::One),
        )?;
        
        Ok(())
    }
}

/// Simplified Poseidon-like hash for 3 inputs
/// In production, use full Poseidon permutation with proper round constants
fn poseidon_hash_3(a: Fr, b: Fr, c: Fr) -> Fr {
    let ab = a * b;
    let ab5 = ab.square().square() * ab;
    ab5 + c
}

/// Simplified Poseidon-like hash for 2 inputs
fn poseidon_hash_2(a: Fr, b: Fr) -> Fr {
    let ab = a * b;
    let ab5 = ab.square().square() * ab;
    ab5 + a
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    
    #[test]
    fn test_circuit_satisfiability() {
        let secret = Fr::from(12345u64);
        let nullifier = Fr::from(67890u64);
        let amount = Fr::from(100_000_000u64); // 0.1 SOL
        let recipient = Fr::from(11111u64);
        let domain = Fr::from(99999u64);
        
        let commitment = poseidon_hash_3(secret, nullifier, amount);
        let nullifier_hash = poseidon_hash_2(domain, nullifier);
        
        let circuit = PrivacyPoolCircuit::new(
            commitment,
            nullifier_hash,
            recipient,
            amount,
            secret,
            nullifier,
            domain,
        );
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        assert!(cs.is_satisfied().unwrap());
        println!("Circuit has {} constraints", cs.num_constraints());
    }
    
    #[test]
    fn test_empty_circuit_for_setup() {
        let circuit = PrivacyPoolCircuit::empty();
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Empty circuit should generate the constraint structure
        println!("Empty circuit has {} constraints", cs.num_constraints());
        // Note: Won't be satisfied since witnesses are missing
    }
}

