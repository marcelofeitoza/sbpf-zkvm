//! Export the verifying key for the simplified Privacy Pool circuit
//! (Only proves commitment knowledge, Merkle membership verified on-chain)

use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use ark_groth16::Groth16;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

const SETUP_SEED: u64 = 0xDEAD_BEEF_CAFE_2024;

/// Simplified circuit - only proves commitment knowledge
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
        let secret_var = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_var = FpVar::new_witness(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // commitment = secret + nullifier * 2^64 + amount * 2^128
        let shift_64 = FpVar::constant(Fr::from(1u64 << 32).square());
        let shift_128 = &shift_64 * &shift_64;
        let computed = &secret_var + &nullifier_var * &shift_64 + &amount_var * &shift_128;
        computed.enforce_equal(&commitment_var)?;

        // nullifier_hash = nullifier^2 + nullifier
        let hash = &nullifier_var * &nullifier_var + &nullifier_var;
        hash.enforce_equal(&nullifier_hash_var)?;

        let _ = &recipient_var * FpVar::constant(Fr::from(1u64));
        Ok(())
    }
}

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

fn bytes_to_hex_array(bytes: &[u8]) -> String {
    let mut s = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 { s.push_str(", "); }
        if i % 16 == 0 && i > 0 { s.push_str("\n    "); }
        s.push_str(&format!("0x{:02x}", b));
    }
    s.push(']');
    s
}

#[test]
fn export_commitment_circuit_vk() {
    println!("\n🔑 Generating Commitment Knowledge Circuit VK...\n");
    
    let mut rng = StdRng::seed_from_u64(SETUP_SEED);
    let (_, vk) = Groth16::<Bn254>::circuit_specific_setup(
        CommitmentKnowledgeCircuit::default(), &mut rng
    ).unwrap();
    
    println!("// Auto-generated VK for CommitmentKnowledgeCircuit");
    println!("// Seed: 0x{:016X}", SETUP_SEED);
    println!("// Public inputs: commitment, nullifier_hash, recipient, amount\n");
    println!("use groth16_solana::groth16::Groth16Verifyingkey;\n");
    
    println!("pub const VK_ALPHA_G1: [u8; 64] = {};", bytes_to_hex_array(&g1_to_be_bytes(vk.alpha_g1)));
    println!();
    println!("pub const VK_BETA_G2: [u8; 128] = {};", bytes_to_hex_array(&g2_to_be_bytes(vk.beta_g2)));
    println!();
    println!("pub const VK_GAMMA_G2: [u8; 128] = {};", bytes_to_hex_array(&g2_to_be_bytes(vk.gamma_g2)));
    println!();
    println!("pub const VK_DELTA_G2: [u8; 128] = {};", bytes_to_hex_array(&g2_to_be_bytes(vk.delta_g2)));
    println!();
    
    println!("pub const VK_IC: [[u8; 64]; {}] = [", vk.gamma_abc_g1.len());
    for (i, ic) in vk.gamma_abc_g1.iter().enumerate() {
        println!("    // IC[{}]", i);
        println!("    {},", bytes_to_hex_array(&g1_to_be_bytes(*ic)));
    }
    println!("];");
    println!();
    
    println!("pub static PRIVACY_POOL_VK: Groth16Verifyingkey = Groth16Verifyingkey {{");
    println!("    nr_pubinputs: {},", vk.gamma_abc_g1.len() - 1);
    println!("    vk_alpha_g1: VK_ALPHA_G1,");
    println!("    vk_beta_g2: VK_BETA_G2,");
    println!("    vk_gamme_g2: VK_GAMMA_G2,");
    println!("    vk_delta_g2: VK_DELTA_G2,");
    println!("    vk_ic: &VK_IC,");
    println!("}};");
}
