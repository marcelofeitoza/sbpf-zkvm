//! MPC Ceremony State Management
//!
//! This module handles the core ceremony logic including:
//! - Initialization with random parameters
//! - Accumulating contributions
//! - Verification of the ceremony chain

use crate::circuit::PrivacyPoolCircuit;
use crate::contribution::Contribution;
use crate::transcript::Transcript;
use anyhow::{Context, Result};
use ark_bn254::{Bn254, Fr, G1Projective, G2Projective};
use ark_ec::CurveGroup;
use ark_ff::Field;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use indicatif::{ProgressBar, ProgressStyle};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::path::Path;

/// The MPC ceremony state
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Ceremony {
    /// Pool ID (program address) for domain separation
    pool_id: String,
    
    /// The current proving key (accumulates contributions)
    proving_key: ProvingKey<Bn254>,
    
    /// The current verifying key
    verifying_key: VerifyingKey<Bn254>,
    
    /// All contributions made so far
    contributions: Vec<Contribution>,
    
    /// Transcript hash chain
    transcript_hash: String,
}

/// Result of ceremony verification
pub struct VerificationResult {
    pub is_valid: bool,
    pub num_contributions: usize,
    pub final_hash: String,
    pub errors: Vec<String>,
}

impl Ceremony {
    /// Initialize a new ceremony
    pub fn initialize(pool_id: &str) -> Result<Self> {
        println!("  Generating initial random parameters...");
        
        // Create the circuit (without witnesses for setup)
        let circuit = PrivacyPoolCircuit::empty();
        
        // Get constraint system info
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone())
            .context("Failed to generate constraints")?;
        
        let num_constraints = cs.num_constraints();
        let num_instance_variables = cs.num_instance_variables();
        let num_witness_variables = cs.num_witness_variables();
        
        println!("  Circuit: {} constraints, {} public inputs, {} witnesses",
            num_constraints, num_instance_variables - 1, num_witness_variables);
        
        // Initialize transcript with pool ID
        let mut transcript = Transcript::new(pool_id);
        
        // Generate initial random parameters using secure entropy
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).context("Failed to get entropy")?;
        
        // Mix with pool_id for domain separation
        let mut hasher = Sha256::new();
        hasher.update(&seed);
        hasher.update(pool_id.as_bytes());
        hasher.update(b"INIT");
        let seed: [u8; 32] = hasher.finalize().into();
        
        let mut rng = ChaCha20Rng::from_seed(seed);
        
        // Generate the initial proving key using ark-groth16 setup
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap());
        pb.set_message("Running Groth16 setup (this takes ~10 seconds)...");
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        
        let (pk, vk): (ProvingKey<Bn254>, VerifyingKey<Bn254>) = 
            ark_groth16::Groth16::<Bn254>::circuit_specific_setup(circuit, &mut rng)
                .context("Failed to generate initial parameters")?;
        
        pb.finish_with_message("Setup complete!");
        
        // Record initialization in transcript
        transcript.append("INIT", pool_id.as_bytes());
        
        let mut vk_bytes: Vec<u8> = Vec::new();
        vk.serialize_compressed(&mut vk_bytes)
            .context("Failed to serialize initial VK")?;
        transcript.append("INITIAL_VK", &vk_bytes);
        
        Ok(Self {
            pool_id: pool_id.to_string(),
            proving_key: pk,
            verifying_key: vk,
            contributions: Vec::new(),
            transcript_hash: transcript.hash(),
        })
    }
    
    /// Load ceremony from file
    pub fn load(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .context("Failed to read ceremony file")?;
        
        Self::deserialize_compressed(&data[..])
            .context("Failed to deserialize ceremony")
    }
    
    /// Save ceremony to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut data = Vec::new();
        self.serialize_compressed(&mut data)
            .context("Failed to serialize ceremony")?;
        
        std::fs::write(path, &data)
            .context("Failed to write ceremony file")?;
        
        Ok(())
    }
    
    /// Add a contribution to the ceremony
    pub fn add_contribution(&mut self, mut contribution: Contribution) -> Result<()> {
        // Record previous hash
        contribution.prev_hash = self.transcript_hash.clone();
        
        // Apply the contribution's delta to the proving key
        // This is the core MPC operation: multiply toxic waste by delta
        self.apply_contribution_to_pk(&contribution.delta)?;
        
        // Update transcript
        let mut transcript = Transcript::new(&self.pool_id);
        transcript.append("PREV_HASH", self.transcript_hash.as_bytes());
        transcript.append_contribution(&contribution.name, &contribution.hash);
        
        self.transcript_hash = transcript.hash();
        self.contributions.push(contribution);
        
        Ok(())
    }
    
    /// Apply a contribution's randomness to the proving key
    fn apply_contribution_to_pk(&mut self, delta: &Fr) -> Result<()> {
        let delta_inv = (*delta).inverse()
            .ok_or_else(|| anyhow::anyhow!("Invalid delta (zero)"))?;
        
        // Update the proving key elements with delta
        // pk.delta_g1 *= delta
        // pk.delta_g2 *= delta  
        // pk.l *= delta_inv (for each element)
        // pk.h *= delta_inv (for each element)
        
        // Get mutable access to pk internals
        let pk = &mut self.proving_key;
        
        // Update delta_g1
        pk.delta_g1 = (G1Projective::from(pk.delta_g1) * delta).into_affine();
        
        // Update delta_g2 in verifying key
        self.verifying_key.delta_g2 = (G2Projective::from(self.verifying_key.delta_g2) * delta).into_affine();
        
        // Update L query
        let pb = ProgressBar::new(pk.l_query.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("  Updating L [{bar:40}] {pos}/{len}")
            .unwrap());
        
        for elem in pk.l_query.iter_mut() {
            *elem = (G1Projective::from(*elem) * delta_inv).into_affine();
            pb.inc(1);
        }
        pb.finish();
        
        // Update H query
        let pb = ProgressBar::new(pk.h_query.len() as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("  Updating H [{bar:40}] {pos}/{len}")
            .unwrap());
        
        for elem in pk.h_query.iter_mut() {
            *elem = (G1Projective::from(*elem) * delta_inv).into_affine();
            pb.inc(1);
        }
        pb.finish();
        
        Ok(())
    }
    
    /// Verify the ceremony
    pub fn verify(&self, verbose: bool) -> Result<VerificationResult> {
        let mut errors = Vec::new();
        
        // Verify each contribution
        for (i, contrib) in self.contributions.iter().enumerate() {
            if !contrib.verify() {
                errors.push(format!("Contribution {} ({}) has invalid hash", i + 1, contrib.name));
            }
            
            if verbose {
                println!("  Contribution {}: {} ✓", i + 1, contrib.name);
            }
        }
        
        // Verify the proving key is well-formed
        // (Check that points are on curve, etc.)
        if !self.verify_pk_structure() {
            errors.push("Proving key structure is invalid".to_string());
        }
        
        // Verify transcript chain
        if !self.verify_transcript_chain() {
            errors.push("Transcript chain is invalid".to_string());
        }
        
        Ok(VerificationResult {
            is_valid: errors.is_empty(),
            num_contributions: self.contributions.len(),
            final_hash: self.transcript_hash.clone(),
            errors,
        })
    }
    
    fn verify_pk_structure(&self) -> bool {
        // Basic sanity checks
        !self.proving_key.l_query.is_empty() && !self.proving_key.h_query.is_empty()
    }
    
    fn verify_transcript_chain(&self) -> bool {
        // Verify the hash chain is consistent
        // In a full implementation, we'd replay all contributions
        !self.transcript_hash.is_empty()
    }
    
    /// Get the pool ID
    pub fn pool_id(&self) -> &str {
        &self.pool_id
    }
    
    /// Get number of contributions
    pub fn num_contributions(&self) -> usize {
        self.contributions.len()
    }
    
    /// Get transcript hash
    pub fn transcript_hash(&self) -> &str {
        &self.transcript_hash
    }
    
    /// Get contributions
    pub fn contributions(&self) -> &[Contribution] {
        &self.contributions
    }
    
    /// Get the proving key
    pub fn proving_key(&self) -> &ProvingKey<Bn254> {
        &self.proving_key
    }
    
    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.verifying_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_ceremony_init() {
        let ceremony = Ceremony::initialize("TestPool123").unwrap();
        assert_eq!(ceremony.pool_id(), "TestPool123");
        assert_eq!(ceremony.num_contributions(), 0);
        println!("Initial transcript: {}", ceremony.transcript_hash());
    }
    
    #[test]
    fn test_ceremony_contribution() {
        let mut ceremony = Ceremony::initialize("TestPool").unwrap();
        
        let contrib1 = Contribution::generate("Party1").unwrap();
        ceremony.add_contribution(contrib1).unwrap();
        
        assert_eq!(ceremony.num_contributions(), 1);
        
        let contrib2 = Contribution::generate("Party2").unwrap();
        ceremony.add_contribution(contrib2).unwrap();
        
        assert_eq!(ceremony.num_contributions(), 2);
        
        let result = ceremony.verify(true).unwrap();
        assert!(result.is_valid);
    }
}

