//! ZK Circuits - Zero-knowledge circuits for BPF instruction verification
//!
//! This crate implements Halo2 circuits for proving correct execution of
//! Solana BPF programs. It defines instruction chips for a minimal BPF subset
//! and provides a circuit for proving counter program execution.

pub mod chips;
pub mod counter;

pub use counter::CounterCircuit;

/// Result type for ZK circuit operations
pub type Result<T> = anyhow::Result<T>;
