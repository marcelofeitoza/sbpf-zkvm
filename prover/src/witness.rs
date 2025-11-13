//! Witness Generation
//!
//! Converts execution traces into circuit witnesses.

use bpf_tracer::{ExecutionTrace, MemoryOperation, RegisterState};
use serde::{Deserialize, Serialize};
use crate::Result;

/// Circuit witness generated from execution trace
///
/// Contains all private witness data needed for circuit synthesis.
/// The witness is organized to match the circuit's constraint structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    /// Initial register state (r0-r10 as field elements)
    pub initial_registers: Vec<u64>,

    /// Register states after each instruction execution
    /// Each element is an array of 11 register values (r0-r10)
    pub instruction_register_states: Vec<Vec<u64>>,

    /// Final register state (r0-r10 as field elements)
    pub final_registers: Vec<u64>,

    /// Program counters for each instruction
    pub program_counters: Vec<u64>,

    /// Instruction bytes for each executed instruction
    pub instruction_bytes: Vec<Vec<u8>>,

    /// Memory operations (address, value, is_write)
    pub memory_operations: Vec<MemoryOp>,
}

/// Memory operation in witness format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOp {
    /// Memory address as field element
    pub address: u64,
    /// Value read or written as field element
    pub value: u64,
    /// 1 if write, 0 if read
    pub is_write: u64,
}

impl Witness {
    /// Create a new witness from an execution trace
    ///
    /// Extracts all witness data and converts it to field element format
    /// suitable for circuit synthesis.
    pub fn from_trace(trace: &ExecutionTrace) -> Result<Self> {
        // Convert initial registers (only r0-r10, not PC)
        let initial_registers = register_state_to_field_elements(&trace.initial_registers);

        // Extract register states after each instruction
        let instruction_register_states: Vec<Vec<u64>> = trace.instructions
            .iter()
            .map(|instr| register_state_to_field_elements(&instr.registers_after))
            .collect();

        // Convert final registers
        let final_registers = register_state_to_field_elements(&trace.final_registers);

        // Extract program counters
        let program_counters: Vec<u64> = trace.instructions
            .iter()
            .map(|instr| instr.pc)
            .collect();

        // Extract instruction bytes
        let instruction_bytes: Vec<Vec<u8>> = trace.instructions
            .iter()
            .map(|instr| instr.instruction_bytes.clone())
            .collect();

        // Convert memory operations
        let memory_operations: Vec<MemoryOp> = trace.memory_ops
            .iter()
            .map(memory_op_to_witness_format)
            .collect();

        Ok(Self {
            initial_registers,
            instruction_register_states,
            final_registers,
            program_counters,
            instruction_bytes,
            memory_operations,
        })
    }

    /// Get the number of instructions in this witness
    pub fn instruction_count(&self) -> usize {
        self.program_counters.len()
    }

    /// Get the number of memory operations in this witness
    pub fn memory_op_count(&self) -> usize {
        self.memory_operations.len()
    }

    /// Serialize witness to bytes for proof generation
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Deserialize witness from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

/// Convert RegisterState to field elements
///
/// Extracts r0-r10 (11 registers) as u64 values that can be
/// converted to field elements during circuit synthesis.
/// Note: PC (r11) is excluded as it's tracked separately.
fn register_state_to_field_elements(regs: &RegisterState) -> Vec<u64> {
    // Only take r0-r10 (11 registers), exclude PC which is at index 11
    regs.regs[0..11].to_vec()
}

/// Convert MemoryOperation to witness format
fn memory_op_to_witness_format(op: &MemoryOperation) -> MemoryOp {
    MemoryOp {
        address: op.address,
        value: op.value,
        is_write: match op.op_type {
            bpf_tracer::MemoryOpType::Write => 1,
            bpf_tracer::MemoryOpType::Read => 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_tracer::{InstructionTrace, MemoryOpType};

    #[test]
    fn test_witness_from_empty_trace() {
        let trace = ExecutionTrace::new();
        let witness = Witness::from_trace(&trace).unwrap();

        assert_eq!(witness.instruction_count(), 0);
        assert_eq!(witness.memory_op_count(), 0);
        assert_eq!(witness.initial_registers.len(), 11);
        assert_eq!(witness.final_registers.len(), 11);
    }

    #[test]
    fn test_witness_from_trace_with_instruction() {
        let initial_regs = RegisterState::from_regs([0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 0]);
        let after_regs = RegisterState::from_regs([0, 52, 20, 30, 40, 50, 60, 70, 80, 90, 100, 8]);
        let final_regs = after_regs.clone();

        let instr = InstructionTrace {
            pc: 0,
            instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00],
            registers_before: initial_regs.clone(),
            registers_after: after_regs,
        };

        let trace = ExecutionTrace {
            instructions: vec![instr],
            memory_ops: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs,
        };

        let witness = Witness::from_trace(&trace).unwrap();

        assert_eq!(witness.instruction_count(), 1);
        assert_eq!(witness.initial_registers, vec![0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        assert_eq!(witness.instruction_register_states[0], vec![0, 52, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        assert_eq!(witness.final_registers, vec![0, 52, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        assert_eq!(witness.program_counters, vec![0]);
    }

    #[test]
    fn test_witness_with_memory_operations() {
        let mem_op = MemoryOperation {
            address: 0x1000,
            value: 0x42,
            op_type: MemoryOpType::Write,
        };

        let mut trace = ExecutionTrace::new();
        trace.memory_ops.push(mem_op);

        let witness = Witness::from_trace(&trace).unwrap();

        assert_eq!(witness.memory_op_count(), 1);
        assert_eq!(witness.memory_operations[0].address, 0x1000);
        assert_eq!(witness.memory_operations[0].value, 0x42);
        assert_eq!(witness.memory_operations[0].is_write, 1);
    }

    #[test]
    fn test_witness_serialization() {
        let trace = ExecutionTrace::new();
        let witness = Witness::from_trace(&trace).unwrap();

        let bytes = witness.to_bytes().unwrap();
        let deserialized = Witness::from_bytes(&bytes).unwrap();

        assert_eq!(witness.instruction_count(), deserialized.instruction_count());
        assert_eq!(witness.initial_registers, deserialized.initial_registers);
    }

    #[test]
    fn test_multiple_instructions() {
        let initial_regs = RegisterState::from_regs([0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 0]);
        let regs_after_1 = RegisterState::from_regs([0, 52, 20, 30, 40, 50, 60, 70, 80, 90, 100, 8]);
        let regs_after_2 = RegisterState::from_regs([0, 94, 20, 30, 40, 50, 60, 70, 80, 90, 100, 16]);
        let final_regs = regs_after_2.clone();

        let instr1 = InstructionTrace {
            pc: 0,
            instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00],
            registers_before: initial_regs.clone(),
            registers_after: regs_after_1.clone(),
        };

        let instr2 = InstructionTrace {
            pc: 8,
            instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00],
            registers_before: regs_after_1,
            registers_after: regs_after_2,
        };

        let trace = ExecutionTrace {
            instructions: vec![instr1, instr2],
            memory_ops: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs,
        };

        let witness = Witness::from_trace(&trace).unwrap();

        assert_eq!(witness.instruction_count(), 2);
        assert_eq!(witness.program_counters, vec![0, 8]);
        assert_eq!(witness.instruction_register_states.len(), 2);
        assert_eq!(witness.instruction_register_states[0], vec![0, 52, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
        assert_eq!(witness.instruction_register_states[1], vec![0, 94, 20, 30, 40, 50, 60, 70, 80, 90, 100]);
    }
}
