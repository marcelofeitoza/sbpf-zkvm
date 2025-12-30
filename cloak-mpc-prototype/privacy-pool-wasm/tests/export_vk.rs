//! Test to export the Groth16 verifying key for the Poseidon-based circuit
//!
//! Run with: cargo test --release export_vk -- --nocapture

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::*, boolean::Boolean};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use std::str::FromStr;

// Same seed as in lib.rs
const SETUP_SEED: u64 = 0xDEAD_BEEF_CAFE_2024;

// Poseidon constants (same as poseidon.rs)
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 57;
const WIDTH: usize = 3;

const ROUND_CONSTANTS: [[&str; WIDTH]; FULL_ROUNDS + PARTIAL_ROUNDS] = include!("../src/poseidon_constants.rs");

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

fn parse_fr(s: &str) -> Fr {
    Fr::from_str(s).unwrap_or_else(|_| Fr::from(0u64))
}

// Poseidon hash gadget (simplified - only what we need for VK generation)
fn poseidon_hash_gadget(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut state: Vec<FpVar<Fr>> = vec![FpVar::constant(Fr::from(0u64))];
    state.extend(inputs.iter().cloned());
    while state.len() < WIDTH {
        state.push(FpVar::constant(Fr::from(0u64)));
    }
    
    let total_rounds = FULL_ROUNDS + PARTIAL_ROUNDS;
    let half_full = FULL_ROUNDS / 2;
    
    for round in 0..total_rounds {
        for (j, s) in state.iter_mut().enumerate() {
            *s = s.clone() + FpVar::constant(parse_fr(ROUND_CONSTANTS[round][j]));
        }
        
        if round < half_full || round >= half_full + PARTIAL_ROUNDS {
            for s in state.iter_mut() {
                let s_clone = s.clone();
                let s2 = s_clone.square()?;
                let s4 = s2.square()?;
                *s = &s4 * &s_clone;
            }
        } else {
            let s0 = state[0].clone();
            let s2 = s0.square()?;
            let s4 = s2.square()?;
            state[0] = &s4 * &s0;
        }
        
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

#[derive(Clone)]
pub struct CommitmentKnowledgeCircuit {
    pub commitment: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub recipient: Option<Fr>,
    pub amount: Option<Fr>,
    pub secret: Option<Fr>,
    pub nullifier: Option<Fr>,
}

impl Default for CommitmentKnowledgeCircuit {
    fn default() -> Self {
        Self {
            commitment: None,
            nullifier_hash: None,
            recipient: None,
            amount: None,
            secret: None,
            nullifier: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for CommitmentKnowledgeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // PUBLIC INPUTS
        let commitment_var = FpVar::new_input(cs.clone(), || {
            self.commitment.ok_or(SynthesisError::AssignmentMissing)
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
        
        // PRIVATE INPUTS
        let secret_var = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_var = FpVar::new_witness(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // CONSTRAINT 1: Commitment = Poseidon(secret, Poseidon(nullifier, amount))
        let inner_hash = poseidon_hash_gadget(cs.clone(), &[nullifier_var.clone(), amount_var.clone()])?;
        let computed_commitment = poseidon_hash_gadget(cs.clone(), &[secret_var.clone(), inner_hash])?;
        computed_commitment.enforce_equal(&commitment_var)?;

        // CONSTRAINT 2: NullifierHash = Poseidon(nullifier, nullifier)
        let computed_nullifier_hash = poseidon_hash_gadget(cs.clone(), &[nullifier_var.clone(), nullifier_var.clone()])?;
        computed_nullifier_hash.enforce_equal(&nullifier_hash_var)?;

        // CONSTRAINT 3: Bind recipient
        let _ = &recipient_var * FpVar::constant(Fr::from(1u64));
        
        // CONSTRAINT 4: Range check on amount (64 bits)
        let amount_bits = amount_var.to_bits_le()?;
        let mut reconstructed = FpVar::constant(Fr::from(0u64));
        let mut power_of_two = FpVar::constant(Fr::from(1u64));
        for bit in amount_bits.iter().take(64) {
            reconstructed = &reconstructed + &power_of_two * FpVar::from(bit.clone());
            power_of_two = &power_of_two + &power_of_two;
        }
        reconstructed.enforce_equal(&amount_var)?;
        
        for bit in amount_bits.iter().skip(64) {
            bit.enforce_equal(&Boolean::constant(false))?;
        }

        Ok(())
    }
}

fn g1_to_bytes_be(p: G1Affine) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    let mut buf = Vec::new();
    p.serialize_uncompressed(&mut buf).unwrap();
    bytes[0..32].copy_from_slice(&buf[0..32].iter().rev().copied().collect::<Vec<_>>());
    bytes[32..64].copy_from_slice(&buf[32..64].iter().rev().copied().collect::<Vec<_>>());
    bytes
}

fn g2_to_bytes_be(p: G2Affine) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    let mut buf = Vec::new();
    p.serialize_uncompressed(&mut buf).unwrap();
    bytes[0..32].copy_from_slice(&buf[32..64].iter().rev().copied().collect::<Vec<_>>());
    bytes[32..64].copy_from_slice(&buf[0..32].iter().rev().copied().collect::<Vec<_>>());
    bytes[64..96].copy_from_slice(&buf[96..128].iter().rev().copied().collect::<Vec<_>>());
    bytes[96..128].copy_from_slice(&buf[64..96].iter().rev().copied().collect::<Vec<_>>());
    bytes
}

#[test]
fn export_vk() {
    println!("\n🔐 Generating Poseidon-based circuit verifying key...\n");
    
    let mut rng = StdRng::seed_from_u64(SETUP_SEED);
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        CommitmentKnowledgeCircuit::default(),
        &mut rng,
    ).expect("Setup failed");
    
    println!("// Auto-generated Poseidon-based circuit verifying key");
    println!("// Seed: 0x{:016X}", SETUP_SEED);
    println!("// Circuit: CommitmentKnowledgeCircuit with Poseidon hash");
    println!();
    
    // Alpha G1
    let alpha = g1_to_bytes_be(vk.alpha_g1);
    println!("pub const VK_ALPHA_G1: [u8; 64] = [");
    for (i, chunk) in alpha.chunks(16).enumerate() {
        print!("    ");
        for b in chunk {
            print!("0x{:02x}, ", b);
        }
        println!();
    }
    println!("];");
    println!();
    
    // Beta G2
    let beta = g2_to_bytes_be(vk.beta_g2);
    println!("pub const VK_BETA_G2: [u8; 128] = [");
    for (i, chunk) in beta.chunks(16).enumerate() {
        print!("    ");
        for b in chunk {
            print!("0x{:02x}, ", b);
        }
        println!();
    }
    println!("];");
    println!();
    
    // Gamma G2
    let gamma = g2_to_bytes_be(vk.gamma_g2);
    println!("pub const VK_GAMMA_G2: [u8; 128] = [");
    for (i, chunk) in gamma.chunks(16).enumerate() {
        print!("    ");
        for b in chunk {
            print!("0x{:02x}, ", b);
        }
        println!();
    }
    println!("];");
    println!();
    
    // Delta G2
    let delta = g2_to_bytes_be(vk.delta_g2);
    println!("pub const VK_DELTA_G2: [u8; 128] = [");
    for (i, chunk) in delta.chunks(16).enumerate() {
        print!("    ");
        for b in chunk {
            print!("0x{:02x}, ", b);
        }
        println!();
    }
    println!("];");
    println!();
    
    // IC points
    println!("pub const VK_IC: [[u8; 64]; {}] = [", vk.gamma_abc_g1.len());
    for (idx, ic) in vk.gamma_abc_g1.iter().enumerate() {
        let ic_bytes = g1_to_bytes_be(*ic);
        println!("    // IC[{}]", idx);
        println!("    [");
        for chunk in ic_bytes.chunks(16) {
            print!("        ");
            for b in chunk {
                print!("0x{:02x}, ", b);
            }
            println!();
        }
        println!("    ],");
    }
    println!("];");
    println!();
    
    println!("// Number of public inputs: {}", vk.gamma_abc_g1.len() - 1);
    println!("\n✅ Copy the above constants to privacy-pool/src/circuit_vk.rs");
}


