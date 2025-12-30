//! Key Export Utilities
//!
//! Export ceremony keys in formats suitable for:
//! - Rust embedded code (for on-chain verifier)
//! - Binary files (for WASM prover)

use crate::ceremony::Ceremony;
use anyhow::{Context, Result};
use ark_bn254::{G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use std::io::Write;
use std::path::Path;

/// Export keys as Rust source code
pub fn export_rust(
    ceremony: &Ceremony,
    pk_path: &Path,
    vk_path: &Path,
) -> Result<()> {
    let vk = ceremony.verifying_key();
    
    // Export verifying key as Rust code (for on-chain program)
    let mut vk_code = String::new();
    vk_code.push_str("//! Auto-generated verifying key from MPC ceremony\n");
    vk_code.push_str("//!\n");
    vk_code.push_str(&format!("//! Pool ID: {}\n", ceremony.pool_id()));
    vk_code.push_str(&format!("//! Contributions: {}\n", ceremony.num_contributions()));
    vk_code.push_str(&format!("//! Transcript hash: {}\n", ceremony.transcript_hash()));
    vk_code.push_str("//!\n");
    vk_code.push_str("//! DO NOT MODIFY - regenerate using mpc-ceremony tool\n\n");
    vk_code.push_str("use groth16_solana::groth16::Groth16Verifyingkey;\n\n");
    
    // Alpha G1
    let alpha_bytes = g1_to_bytes(&vk.alpha_g1);
    vk_code.push_str(&format_bytes_const("VK_ALPHA_G1", &alpha_bytes, 64));
    
    // Beta G2
    let beta_bytes = g2_to_bytes(&vk.beta_g2);
    vk_code.push_str(&format_bytes_const("VK_BETA_G2", &beta_bytes, 128));
    
    // Gamma G2
    let gamma_bytes = g2_to_bytes(&vk.gamma_g2);
    vk_code.push_str(&format_bytes_const("VK_GAMMA_G2", &gamma_bytes, 128));
    
    // Delta G2
    let delta_bytes = g2_to_bytes(&vk.delta_g2);
    vk_code.push_str(&format_bytes_const("VK_DELTA_G2", &delta_bytes, 128));
    
    // IC (Gamma ABC)
    let ic_count = vk.gamma_abc_g1.len();
    vk_code.push_str(&format!("pub const VK_IC: [[u8; 64]; {}] = [\n", ic_count));
    for (i, ic) in vk.gamma_abc_g1.iter().enumerate() {
        let ic_bytes = g1_to_bytes(ic);
        vk_code.push_str(&format!("    // IC[{}]\n", i));
        vk_code.push_str("    [\n");
        for chunk in ic_bytes.chunks(16) {
            vk_code.push_str("        ");
            for b in chunk {
                vk_code.push_str(&format!("0x{:02x}, ", b));
            }
            vk_code.push('\n');
        }
        vk_code.push_str("    ],\n");
    }
    vk_code.push_str("];\n\n");
    
    // Verifying key constant
    vk_code.push_str(&format!(
        r#"pub const PRIVACY_POOL_VK: Groth16Verifyingkey = Groth16Verifyingkey {{
    nr_pubinputs: {},
    vk_alpha_g1: VK_ALPHA_G1,
    vk_beta_g2: VK_BETA_G2,
    vk_gamme_g2: VK_GAMMA_G2,
    vk_delta_g2: VK_DELTA_G2,
    vk_ic: &VK_IC,
}};
"#,
        ic_count - 1 // Public inputs count (excluding 1)
    ));
    
    std::fs::write(vk_path, vk_code)
        .context("Failed to write verifying key")?;
    
    // Export proving key reference (for documentation)
    let mut pk_code = String::new();
    pk_code.push_str("//! Proving key reference from MPC ceremony\n");
    pk_code.push_str("//!\n");
    pk_code.push_str(&format!("//! Pool ID: {}\n", ceremony.pool_id()));
    pk_code.push_str(&format!("//! Contributions: {}\n", ceremony.num_contributions()));
    pk_code.push_str(&format!("//! Transcript hash: {}\n", ceremony.transcript_hash()));
    pk_code.push_str("//!\n");
    pk_code.push_str("//! The proving key is too large to embed in code.\n");
    pk_code.push_str("//! Use the binary export format and load at runtime.\n\n");
    pk_code.push_str("/// Size of the proving key in bytes\n");
    
    let mut pk_bytes = Vec::new();
    ceremony.proving_key().serialize_compressed(&mut pk_bytes)?;
    pk_code.push_str(&format!("pub const PROVING_KEY_SIZE: usize = {};\n", pk_bytes.len()));
    
    std::fs::write(pk_path, pk_code)
        .context("Failed to write proving key reference")?;
    
    Ok(())
}

/// Export keys as binary files
pub fn export_binary(
    ceremony: &Ceremony,
    pk_path: &Path,
    vk_path: &Path,
) -> Result<()> {
    // Export proving key
    let mut pk_bytes = Vec::new();
    ceremony.proving_key().serialize_compressed(&mut pk_bytes)
        .context("Failed to serialize proving key")?;
    std::fs::write(pk_path, &pk_bytes)
        .context("Failed to write proving key")?;
    
    // Export verifying key in groth16-solana format
    let vk = ceremony.verifying_key();
    let mut vk_file = std::fs::File::create(vk_path)
        .context("Failed to create verifying key file")?;
    
    // Write header
    vk_file.write_all(b"GROTH16_VK_V1")?;
    
    // Write pool ID
    let pool_id_bytes = ceremony.pool_id().as_bytes();
    vk_file.write_all(&(pool_id_bytes.len() as u32).to_le_bytes())?;
    vk_file.write_all(pool_id_bytes)?;
    
    // Write transcript hash
    let hash_bytes = ceremony.transcript_hash().as_bytes();
    vk_file.write_all(&(hash_bytes.len() as u32).to_le_bytes())?;
    vk_file.write_all(hash_bytes)?;
    
    // Write key components
    vk_file.write_all(&g1_to_bytes(&vk.alpha_g1))?;
    vk_file.write_all(&g2_to_bytes(&vk.beta_g2))?;
    vk_file.write_all(&g2_to_bytes(&vk.gamma_g2))?;
    vk_file.write_all(&g2_to_bytes(&vk.delta_g2))?;
    
    // Write IC
    vk_file.write_all(&(vk.gamma_abc_g1.len() as u32).to_le_bytes())?;
    for ic in &vk.gamma_abc_g1 {
        vk_file.write_all(&g1_to_bytes(ic))?;
    }
    
    Ok(())
}

/// Convert G1 point to bytes in groth16-solana format
fn g1_to_bytes(point: &G1Affine) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    
    if point.is_zero() {
        bytes.extend_from_slice(&[0u8; 64]);
        return bytes;
    }
    
    // Get x and y coordinates
    let x = point.x().unwrap();
    let y = point.y().unwrap();
    
    // Serialize in big-endian format (as expected by alt_bn128)
    let mut x_bytes = Vec::new();
    x.serialize_compressed(&mut x_bytes).unwrap();
    
    let mut y_bytes = Vec::new();
    y.serialize_compressed(&mut y_bytes).unwrap();
    
    // Reverse for big-endian
    x_bytes.reverse();
    y_bytes.reverse();
    
    // Pad to 32 bytes each
    while x_bytes.len() < 32 {
        x_bytes.insert(0, 0);
    }
    while y_bytes.len() < 32 {
        y_bytes.insert(0, 0);
    }
    
    bytes.extend_from_slice(&x_bytes[..32]);
    bytes.extend_from_slice(&y_bytes[..32]);
    
    bytes
}

/// Convert G2 point to bytes in groth16-solana format
fn g2_to_bytes(point: &G2Affine) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(128);
    
    if point.is_zero() {
        bytes.extend_from_slice(&[0u8; 128]);
        return bytes;
    }
    
    // G2 points have x and y in Fp2 (each is c0 + c1*u)
    let x = point.x().unwrap();
    let y = point.y().unwrap();
    
    // Serialize each component
    let mut x_c1_bytes = Vec::new();
    let mut x_c0_bytes = Vec::new();
    let mut y_c1_bytes = Vec::new();
    let mut y_c0_bytes = Vec::new();
    
    x.c1.serialize_compressed(&mut x_c1_bytes).unwrap();
    x.c0.serialize_compressed(&mut x_c0_bytes).unwrap();
    y.c1.serialize_compressed(&mut y_c1_bytes).unwrap();
    y.c0.serialize_compressed(&mut y_c0_bytes).unwrap();
    
    // Reverse for big-endian
    x_c1_bytes.reverse();
    x_c0_bytes.reverse();
    y_c1_bytes.reverse();
    y_c0_bytes.reverse();
    
    // Pad each to 32 bytes
    while x_c1_bytes.len() < 32 { x_c1_bytes.insert(0, 0); }
    while x_c0_bytes.len() < 32 { x_c0_bytes.insert(0, 0); }
    while y_c1_bytes.len() < 32 { y_c1_bytes.insert(0, 0); }
    while y_c0_bytes.len() < 32 { y_c0_bytes.insert(0, 0); }
    
    // Order: x_c1, x_c0, y_c1, y_c0 (groth16-solana format)
    bytes.extend_from_slice(&x_c1_bytes[..32]);
    bytes.extend_from_slice(&x_c0_bytes[..32]);
    bytes.extend_from_slice(&y_c1_bytes[..32]);
    bytes.extend_from_slice(&y_c0_bytes[..32]);
    
    bytes
}

/// Format a byte array as a Rust const
fn format_bytes_const(name: &str, bytes: &[u8], expected_len: usize) -> String {
    let mut s = format!("pub const {}: [u8; {}] = [\n", name, expected_len);
    
    for chunk in bytes.chunks(16) {
        s.push_str("    ");
        for b in chunk {
            s.push_str(&format!("0x{:02x}, ", b));
        }
        s.push('\n');
    }
    
    s.push_str("];\n\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G1Projective;
    use ark_ec::CurveGroup;
    use ark_std::UniformRand;
    
    #[test]
    fn test_g1_serialization() {
        let mut rng = ark_std::test_rng();
        let point = G1Projective::rand(&mut rng).into_affine();
        let bytes = g1_to_bytes(&point);
        assert_eq!(bytes.len(), 64);
    }
    
    #[test]
    fn test_g2_serialization() {
        let mut rng = ark_std::test_rng();
        let point: G2Affine = ark_bn254::G2Projective::rand(&mut rng).into_affine();
        let bytes = g2_to_bytes(&point);
        assert_eq!(bytes.len(), 128);
    }
}


