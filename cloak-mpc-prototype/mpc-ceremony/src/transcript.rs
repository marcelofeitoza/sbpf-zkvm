//! Ceremony Transcript
//!
//! Maintains a running hash of all ceremony events for verifiability.

use sha2::{Digest, Sha256};

/// A transcript that accumulates ceremony events into a hash chain
#[derive(Clone, Debug)]
pub struct Transcript {
    hasher: Sha256,
    current_hash: String,
}

impl Transcript {
    /// Create a new transcript with the given domain separator
    pub fn new(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"CLOAK_MPC_CEREMONY_v1");
        hasher.update(domain.as_bytes());
        
        let current = hasher.clone().finalize();
        
        Self {
            hasher,
            current_hash: hex::encode(current),
        }
    }
    
    /// Add a labeled message to the transcript
    pub fn append(&mut self, label: &str, data: &[u8]) {
        self.hasher.update(label.as_bytes());
        self.hasher.update(&(data.len() as u64).to_le_bytes());
        self.hasher.update(data);
        
        self.current_hash = hex::encode(self.hasher.clone().finalize());
    }
    
    /// Add a contribution to the transcript
    pub fn append_contribution(&mut self, name: &str, hash: &str) {
        self.append("CONTRIBUTION", format!("{}:{}", name, hash).as_bytes());
    }
    
    /// Get the current transcript hash
    pub fn hash(&self) -> String {
        self.current_hash.clone()
    }
    
    /// Finalize and get the transcript hash
    pub fn finalize(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new("default")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new("test_pool");
        let mut t2 = Transcript::new("test_pool");
        
        t1.append("data", b"hello");
        t2.append("data", b"hello");
        
        assert_eq!(t1.hash(), t2.hash());
    }
    
    #[test]
    fn test_transcript_different_domains() {
        let t1 = Transcript::new("pool_a");
        let t2 = Transcript::new("pool_b");
        
        assert_ne!(t1.hash(), t2.hash());
    }
}


