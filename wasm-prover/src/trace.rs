//! Trace Data Structures
//!
//! Self-contained trace structures for WASM.
//! These mirror the bpf-tracer types but without external dependencies.

use serde::{Deserialize, Serialize};

/// Complete execution trace of a BPF program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Vector of instruction traces in execution order
    pub instructions: Vec<InstructionTrace>,
    /// Initial register state at program start
    pub initial_registers: RegisterState,
    /// Final register state at program exit
    pub final_registers: RegisterState,
}

/// Trace of a single instruction execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionTrace {
    /// Program counter (instruction address)
    pub pc: u64,
    /// Raw instruction bytes (8 bytes)
    pub instruction_bytes: Vec<u8>,
    /// Register state before instruction execution
    pub registers_before: RegisterState,
    /// Register state after instruction execution
    pub registers_after: RegisterState,
}

/// State of all BPF registers (r0-r10) and PC (r11)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterState {
    /// General purpose registers r0-r10 and PC (r11)
    /// r0: return value
    /// r1-r5: function arguments
    /// r6-r9: callee saved
    /// r10: frame pointer (read-only)
    /// r11: program counter
    pub regs: [u64; 12],
}

impl RegisterState {
    /// Create new register state with all zeros
    pub fn new() -> Self {
        Self { regs: [0; 12] }
    }
    
    /// Create register state from array
    pub fn from_array(regs: [u64; 12]) -> Self {
        Self { regs }
    }
}

impl Default for RegisterState {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionTrace {
    /// Create new empty execution trace
    pub fn new() -> Self {
        Self {
            instructions: Vec::new(),
            initial_registers: RegisterState::new(),
            final_registers: RegisterState::new(),
        }
    }
    
    /// Get number of instructions executed
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
    
    /// Pad trace to a fixed size with NOP instructions
    pub fn pad_to_size(&mut self, target_size: usize) {
        if self.instructions.len() >= target_size {
            self.instructions.truncate(target_size);
            return;
        }
        
        let last_regs = if self.instructions.is_empty() {
            self.initial_registers.clone()
        } else {
            self.instructions.last().unwrap().registers_after.clone()
        };
        
        // Pad with NOP instructions
        while self.instructions.len() < target_size {
            self.instructions.push(InstructionTrace {
                pc: 0,
                instruction_bytes: vec![0x00; 8], // NOP
                registers_before: last_regs.clone(),
                registers_after: last_regs.clone(),
            });
        }
    }
}

impl Default for ExecutionTrace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_register_state() {
        let regs = RegisterState::new();
        assert_eq!(regs.regs, [0; 12]);
    }
    
    #[test]
    fn test_trace_padding() {
        let mut trace = ExecutionTrace::new();
        trace.pad_to_size(10);
        assert_eq!(trace.instructions.len(), 10);
    }
}

