//! BPF Instruction Chips
//!
//! Defines the trait and implementations for individual BPF instruction chips.

use crate::Result;

/// Trait for BPF instruction chips
///
/// Each instruction type implements this trait to define its
/// constraint system in the ZK circuit.
pub trait BpfInstructionChip {
    /// Synthesize the constraints for this instruction
    ///
    /// This method should add all necessary constraints to prove
    /// that the instruction was executed correctly.
    fn synthesize(&self) -> Result<()>;
}

// Instruction chip implementations will be added here
// - ALU64_ADD_IMM: Add immediate to 64-bit register
// - ALU64_ADD_REG: Add register to register
// - STW: Store 64-bit word to memory
// - LDW: Load 64-bit word from memory
// - EXIT: Program exit
