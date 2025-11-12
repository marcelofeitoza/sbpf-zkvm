//! BPF Tracer - Execution trace capture for Solana BPF programs
//!
//! This crate wraps the solana-sbpf VM to instrument and record complete
//! execution traces including register state, memory operations, and instruction flow.

pub mod trace;
pub mod vm;

pub use trace::{ExecutionTrace, InstructionTrace, MemoryOperation, RegisterState};
pub use vm::trace_program;

/// Result type for BPF tracer operations
pub type Result<T> = anyhow::Result<T>;
