//! Public Inputs
//!
//! Defines the public inputs to the ZK circuit (state commitments).

use bpf_tracer::ExecutionTrace;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use crate::Result;

/// Public inputs to the counter circuit
///
/// These values are public (visible to the verifier) and represent
/// commitments to the initial and final program state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Hash of initial counter value
    pub initial_value_hash: [u8; 32],
    /// Hash of final counter value
    pub final_value_hash: [u8; 32],
}

impl PublicInputs {
    /// Create public inputs from an execution trace
    ///
    /// Computes commitments to the initial and final state
    /// from the trace's register states.
    pub fn from_trace(trace: &ExecutionTrace) -> Result<Self> {
        // Hash initial register state
        let initial_bytes = serde_json::to_vec(&trace.initial_registers)?;
        let initial_hash = Sha256::digest(&initial_bytes);

        // Hash final register state
        let final_bytes = serde_json::to_vec(&trace.final_registers)?;
        let final_hash = Sha256::digest(&final_bytes);

        Ok(Self {
            initial_value_hash: initial_hash.into(),
            final_value_hash: final_hash.into(),
        })
    }

    /// Get initial value hash as hex string
    pub fn initial_hash_hex(&self) -> String {
        hex::encode(self.initial_value_hash)
    }

    /// Get final value hash as hex string
    pub fn final_hash_hex(&self) -> String {
        hex::encode(self.final_value_hash)
    }
}
