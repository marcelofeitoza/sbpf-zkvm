//! Poseidon Hash Implementation for ZK Circuits
//!
//! This module implements Poseidon hash both natively and as R1CS constraints.
//! Uses the same parameters as light-poseidon (Circom-compatible) for consistency
//! with on-chain verification.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::str::FromStr;

// Poseidon parameters for BN254 (Circom-compatible, width=3 for 2 inputs)
// These are the standard parameters used by light-poseidon and circomlib

/// Number of full rounds
const FULL_ROUNDS: usize = 8;

/// Number of partial rounds  
const PARTIAL_ROUNDS: usize = 57;

/// State width (t = 3 for 2 inputs + 1 capacity)
const WIDTH: usize = 3;

/// Round constants for Poseidon (BN254, t=3, RF=8, RP=57)
/// Generated using the Poseidon paper's method
const ROUND_CONSTANTS: [[&str; WIDTH]; FULL_ROUNDS + PARTIAL_ROUNDS] = include!("poseidon_constants.rs");

/// MDS matrix for Poseidon (BN254, t=3)
const MDS_MATRIX: [[&str; WIDTH]; WIDTH] = [
    [
        "7511745149465107256748700652201246547602992235352608707588321460060273774987",
        "10370080108974718697676803824769673834027675643658433702224577712625900127200",
        "19705173408229649878903981084052839426532978878058043055305024233888854471533",
    ],
    [
        "18732019378264290557468133440468564866454307626475683536618613112504878618481",
        "20870176810702568768751421378473869562658540583882454726129544628203806653987",
        "7266061498423634438633389053804536045105766754026813321943009179476902321146",
    ],
    [
        "9131299761947733513298312097611845208338517739621853568979632113419485819303",
        "10595341252162738537912664445405114076324478519622938027420701542910180337937",
        "11597556804922396090267472882856054602429588299176362916247939723151043581408",
    ],
];

/// Parse a decimal string to Fr
fn parse_fr(s: &str) -> Fr {
    Fr::from_str(s).unwrap_or_else(|_| Fr::from(0u64))
}

/// Native Poseidon hash implementation (matches light-poseidon)
pub fn poseidon_hash(inputs: &[Fr]) -> Fr {
    assert!(inputs.len() <= 2, "Poseidon only supports up to 2 inputs");
    
    // Initialize state with capacity element = 0 and inputs
    let mut state = [Fr::from(0u64); WIDTH];
    for (i, input) in inputs.iter().enumerate() {
        state[i + 1] = *input;
    }
    
    let total_rounds = FULL_ROUNDS + PARTIAL_ROUNDS;
    let half_full = FULL_ROUNDS / 2;
    
    for round in 0..total_rounds {
        // Add round constants
        for (j, s) in state.iter_mut().enumerate() {
            *s += parse_fr(ROUND_CONSTANTS[round][j]);
        }
        
        // S-box: x^5
        if round < half_full || round >= half_full + PARTIAL_ROUNDS {
            // Full round: apply S-box to all elements
            for s in state.iter_mut() {
                let s2 = s.square();
                let s4 = s2.square();
                *s = s4 * *s;
            }
        } else {
            // Partial round: apply S-box only to first element
            let s2 = state[0].square();
            let s4 = s2.square();
            state[0] = s4 * state[0];
        }
        
        // MDS matrix multiplication
        let mut new_state = [Fr::from(0u64); WIDTH];
        for (i, ns) in new_state.iter_mut().enumerate() {
            for (j, s) in state.iter().enumerate() {
                *ns += parse_fr(MDS_MATRIX[i][j]) * s;
            }
        }
        state = new_state;
    }
    
    state[0]
}

/// Poseidon hash gadget for R1CS constraints
pub struct PoseidonGadget;

impl PoseidonGadget {
    /// Compute Poseidon hash with R1CS constraints
    pub fn hash(
        cs: ConstraintSystemRef<Fr>,
        inputs: &[FpVar<Fr>],
    ) -> Result<FpVar<Fr>, SynthesisError> {
        assert!(inputs.len() <= 2, "Poseidon gadget supports up to 2 inputs");
        
        // Initialize state with capacity element = 0 and inputs
        let mut state: Vec<FpVar<Fr>> = vec![FpVar::constant(Fr::from(0u64))];
        state.extend(inputs.iter().cloned());
        while state.len() < WIDTH {
            state.push(FpVar::constant(Fr::from(0u64)));
        }
        
        let total_rounds = FULL_ROUNDS + PARTIAL_ROUNDS;
        let half_full = FULL_ROUNDS / 2;
        
        for round in 0..total_rounds {
            // Add round constants
            for (j, s) in state.iter_mut().enumerate() {
                *s = s.clone() + FpVar::constant(parse_fr(ROUND_CONSTANTS[round][j]));
            }
            
            // S-box: x^5
            if round < half_full || round >= half_full + PARTIAL_ROUNDS {
                // Full round: apply S-box to all elements
                for s in state.iter_mut() {
                    let s_clone = s.clone();
                    let s2 = s_clone.square()?;
                    let s4 = s2.square()?;
                    *s = &s4 * &s_clone;
                }
            } else {
                // Partial round: apply S-box only to first element
                let s0 = state[0].clone();
                let s2 = s0.square()?;
                let s4 = s2.square()?;
                state[0] = &s4 * &s0;
            }
            
            // MDS matrix multiplication
            let mut new_state = Vec::with_capacity(WIDTH);
            for i in 0..WIDTH {
                let mut acc = FpVar::constant(Fr::from(0u64));
                for (j, s) in state.iter().enumerate() {
                    acc = acc + FpVar::constant(parse_fr(MDS_MATRIX[i][j])) * s;
                }
                new_state.push(acc);
            }
            state = new_state;
        }
        
        Ok(state[0].clone())
    }
    
    /// Hash 2 inputs (convenience function)
    pub fn hash2(
        cs: ConstraintSystemRef<Fr>,
        a: &FpVar<Fr>,
        b: &FpVar<Fr>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        Self::hash(cs, &[a.clone(), b.clone()])
    }
}

/// Compute commitment = Poseidon(secret, Poseidon(nullifier, amount))
pub fn compute_commitment(secret: Fr, nullifier: Fr, amount: Fr) -> Fr {
    let inner = poseidon_hash(&[nullifier, amount]);
    poseidon_hash(&[secret, inner])
}

/// Compute nullifier_hash = Poseidon(nullifier, nullifier)
/// NOTE: This is the legacy version without domain separation
pub fn compute_nullifier_hash(nullifier: Fr) -> Fr {
    poseidon_hash(&[nullifier, nullifier])
}

/// Compute nullifier_hash with domain separation = Poseidon(domain, nullifier)
/// This binds the nullifier to a specific pool, preventing cross-pool replay attacks
pub fn compute_nullifier_hash_with_domain(domain: Fr, nullifier: Fr) -> Fr {
    poseidon_hash(&[domain, nullifier])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    
    #[test]
    fn test_poseidon_native() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let hash = poseidon_hash(&[a, b]);
        
        // Hash should be deterministic
        let hash2 = poseidon_hash(&[a, b]);
        assert_eq!(hash, hash2);
        
        // Different inputs should give different hash
        let hash3 = poseidon_hash(&[a, Fr::from(3u64)]);
        assert_ne!(hash, hash3);
    }
    
    #[test]
    fn test_poseidon_gadget_matches_native() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);
        
        let a_var = FpVar::new_witness(cs.clone(), || Ok(a)).unwrap();
        let b_var = FpVar::new_witness(cs.clone(), || Ok(b)).unwrap();
        
        let hash_gadget = PoseidonGadget::hash2(cs.clone(), &a_var, &b_var).unwrap();
        let hash_native = poseidon_hash(&[a, b]);
        
        // Gadget should produce same result as native
        assert_eq!(hash_gadget.value().unwrap(), hash_native);
        
        // Constraints should be satisfied
        assert!(cs.is_satisfied().unwrap());
    }
}

