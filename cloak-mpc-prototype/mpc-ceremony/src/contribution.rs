//! MPC Contribution handling
//!
//! Each contribution adds entropy to the ceremony parameters.

use anyhow::{Context, Result};
use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// A single contribution to the MPC ceremony
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Contribution {
    /// Participant name/identifier
    pub name: String,
    
    /// Timestamp of contribution
    pub timestamp: String,
    
    /// Hash of this contribution (for verification)
    pub hash: String,
    
    /// The random scalar used (kept private during ceremony, revealed if verification needed)
    /// In a real ceremony, this is the "toxic waste" that MUST be deleted
    pub(crate) delta: Fr,
    
    /// Hash of the ceremony state before this contribution
    pub(crate) prev_hash: String,
}

impl Contribution {
    /// Generate a new contribution using secure OS randomness
    pub fn generate(name: &str) -> Result<Self> {
        // Get entropy from OS
        let mut os_entropy = [0u8; 32];
        getrandom::getrandom(&mut os_entropy)
            .context("Failed to get OS entropy")?;
        
        // Mix with timestamp for additional entropy
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        
        let mut hasher = Sha256::new();
        hasher.update(&os_entropy);
        hasher.update(&timestamp.to_le_bytes());
        let seed: [u8; 32] = hasher.finalize().into();
        
        let mut rng = ChaCha20Rng::from_seed(seed);
        let delta = Fr::rand(&mut rng);
        
        let timestamp_str = chrono_timestamp();
        
        // Hash of contribution (without revealing delta)
        let hash = contribution_hash(name, &timestamp_str, &delta);
        
        Ok(Self {
            name: name.to_string(),
            timestamp: timestamp_str,
            hash,
            delta,
            prev_hash: String::new(), // Set by ceremony
        })
    }
    
    /// Create contribution from provided entropy (for reproducibility/audit)
    pub fn from_entropy(hex_entropy: &str, name: &str) -> Result<Self> {
        let entropy_bytes = hex::decode(hex_entropy)
            .context("Invalid hex entropy")?;
        
        if entropy_bytes.len() < 32 {
            anyhow::bail!("Entropy must be at least 32 bytes");
        }
        
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&entropy_bytes[..32]);
        
        let mut rng = ChaCha20Rng::from_seed(seed);
        let delta = Fr::rand(&mut rng);
        
        let timestamp_str = chrono_timestamp();
        let hash = contribution_hash(name, &timestamp_str, &delta);
        
        Ok(Self {
            name: name.to_string(),
            timestamp: timestamp_str,
            hash,
            delta,
            prev_hash: String::new(),
        })
    }
    
    /// Verify this contribution is valid
    pub fn verify(&self) -> bool {
        let expected_hash = contribution_hash(&self.name, &self.timestamp, &self.delta);
        self.hash == expected_hash
    }
}

/// Generate a hash of the contribution for verification
fn contribution_hash(name: &str, timestamp: &str, delta: &Fr) -> String {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(timestamp.as_bytes());
    
    // Serialize delta
    let mut delta_bytes = Vec::new();
    delta.serialize_compressed(&mut delta_bytes).unwrap();
    hasher.update(&delta_bytes);
    
    hex::encode(hasher.finalize())
}

/// Get current timestamp as ISO 8601 string
fn chrono_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();
    
    // Simple ISO-like format without chrono dependency
    let secs = now.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    
    // Days since 1970-01-01
    let (year, month, day) = days_to_ymd(days);
    
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since epoch to year/month/day
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simplified calendar calculation
    let mut year = 1970;
    let mut remaining = days;
    
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    
    let months: [u64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    
    let mut month = 1;
    for days_in_month in months {
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }
    
    (year, month, remaining + 1)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_contribution_generation() {
        let contrib = Contribution::generate("TestParty").unwrap();
        assert_eq!(contrib.name, "TestParty");
        assert!(contrib.verify());
        println!("Generated contribution: {:?}", contrib.hash);
    }
    
    #[test]
    fn test_contribution_from_entropy() {
        let entropy = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let contrib = Contribution::from_entropy(entropy, "EntropyParty").unwrap();
        assert!(contrib.verify());
    }
    
    #[test]
    fn test_timestamp() {
        let ts = chrono_timestamp();
        println!("Timestamp: {}", ts);
        assert!(ts.contains("T"));
        assert!(ts.contains("Z"));
    }
}

