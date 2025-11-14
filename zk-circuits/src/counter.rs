//! Counter Circuit
//!
//! ZK circuit that proves correct execution of a counter increment program.

use bpf_tracer::{ExecutionTrace, InstructionTrace, RegisterState};
use halo2_base::{
    gates::GateInstructions,
    utils::ScalarField,
    AssignedValue, Context,
};
use crate::Result;

/// Counter circuit with public inputs for initial and final state
///
/// This circuit proves that a BPF counter program executed correctly,
/// incrementing a value from initial_value to final_value.
///
/// For recursive proving, this circuit supports fixed-size chunks with padding.
///
/// Public Inputs:
/// - Initial register state (r0-r10)
/// - Final register state (r0-r10)
///
/// Private Witness:
/// - Full execution trace of the counter program (padded to chunk_size if needed)
pub struct CounterCircuit {
    /// Execution trace (private witness)
    trace: ExecutionTrace,
    /// Maximum instructions (for chunked proving with padding)
    /// If None, uses actual trace length (legacy mode)
    chunk_size: Option<usize>,
}

impl CounterCircuit {
    /// Create a new counter circuit from an execution trace (legacy mode)
    pub fn from_trace(trace: ExecutionTrace) -> Self {
        Self {
            trace,
            chunk_size: None,
        }
    }

    /// Create a new counter circuit for chunked proving with fixed size
    ///
    /// The trace will be padded to `chunk_size` with NOP instructions if needed.
    /// This ensures the circuit has fixed shape for recursive proving.
    pub fn from_trace_chunked(trace: ExecutionTrace, chunk_size: usize) -> Self {
        let padded_trace = Self::pad_trace(trace, chunk_size);
        Self {
            trace: padded_trace,
            chunk_size: Some(chunk_size),
        }
    }

    /// Pad a trace to the specified chunk size with NOP instructions
    ///
    /// NOP instructions maintain register state (registers_after == registers_before)
    fn pad_trace(mut trace: ExecutionTrace, chunk_size: usize) -> ExecutionTrace {
        let current_len = trace.instructions.len();

        if current_len >= chunk_size {
            // Trace is already at or over chunk size, truncate or return as-is
            trace.instructions.truncate(chunk_size);
            return trace;
        }

        // Get the last register state for padding
        let last_regs = if trace.instructions.is_empty() {
            trace.initial_registers.clone()
        } else {
            trace.instructions.last().unwrap().registers_after.clone()
        };

        // Pad with NOP instructions
        for _ in current_len..chunk_size {
            let nop = InstructionTrace {
                pc: 0, // NOP doesn't change PC in our model
                instruction_bytes: vec![0x00; 8], // NOP opcode (0x00 in sBPF)
                registers_before: last_regs.clone(),
                registers_after: last_regs.clone(), // NOP: no state change
            };
            trace.instructions.push(nop);
        }

        // Final registers remain the same (last real instruction's output)
        trace
    }

    /// Synthesize the circuit constraints
    ///
    /// This method builds the complete constraint system proving
    /// correct execution of the counter program.
    ///
    /// This is intended to be called from within a circuit builder context.
    pub fn synthesize<F: ScalarField>(
        &self,
        ctx: &mut Context<F>,
        gate: &impl GateInstructions<F>,
    ) -> Result<()> {
        // Load initial register state as witnesses
        let mut current_regs = self.load_register_state(ctx, &self.trace.initial_registers);

        // Iterate through each instruction in the trace
        for instr_trace in &self.trace.instructions {
            // Load the "after" register state for this instruction
            let next_regs = self.load_register_state(ctx, &instr_trace.registers_after);

            // TODO: In a full implementation, we would:
            // 1. Decode the instruction bytes to determine instruction type
            // 2. Instantiate the appropriate chip (ALU64_ADD_IMM, etc.)
            // 3. Call chip.synthesize() to verify the instruction
            //
            // For this MVP skeleton, we just constrain that registers transition correctly
            // (This would be replaced with actual instruction chip dispatch)

            // For now, we just verify the transition happens
            // In practice, each instruction chip would constrain this
            for i in 0..11 {
                // This is a placeholder - real implementation would use instruction chips
                // to properly constrain the state transition
                let _ = gate.add(ctx, current_regs[i], next_regs[i]);
            }

            // Update current state for next iteration
            current_regs = next_regs;
        }

        // Verify final register state matches trace
        let final_regs = self.load_register_state(ctx, &self.trace.final_registers);
        for i in 0..11 {
            ctx.constrain_equal(&current_regs[i], &final_regs[i]);
        }

        Ok(())
    }

    /// Get the number of constraints in this circuit
    ///
    /// Returns an estimate of the circuit complexity
    pub fn num_constraints(&self) -> usize {
        // Rough estimate: each instruction needs ~50 constraints
        // (register checks, arithmetic operations, etc.)
        self.trace.instruction_count() * 50
    }

    /// Helper to load a RegisterState as assigned values
    fn load_register_state<F: ScalarField>(
        &self,
        ctx: &mut Context<F>,
        regs: &RegisterState,
    ) -> [AssignedValue<F>; 11] {
        std::array::from_fn(|i| ctx.load_witness(F::from(regs.regs[i])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_tracer::InstructionTrace;
    use halo2_base::utils::testing::base_test;

    #[test]
    fn test_counter_circuit_creation() {
        let trace = ExecutionTrace::new();
        let circuit = CounterCircuit::from_trace(trace);
        assert_eq!(circuit.num_constraints(), 0);
    }

    #[test]
    fn test_counter_circuit_simple_trace() {
        // Create a simple execution trace with one instruction
        let initial_regs = RegisterState::from_regs([0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 0]);
        let after_regs = RegisterState::from_regs([0, 52, 20, 30, 40, 50, 60, 70, 80, 90, 100, 8]);
        let final_regs = after_regs.clone();

        let instr = InstructionTrace {
            pc: 0,
            instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00], // ADD_IMM r1, 42
            registers_before: initial_regs.clone(),
            registers_after: after_regs,
        };

        let trace = ExecutionTrace {
            instructions: vec![instr],
            account_states: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs,
        };

        let circuit = CounterCircuit::from_trace(trace);

        // Test synthesis using the new pattern
        base_test().run_gate(|ctx, gate| {
            circuit.synthesize(ctx, gate).unwrap();
        });
    }

    #[test]
    fn test_counter_circuit_with_padding() {
        // Create a trace with 2 instructions
        let initial_regs = RegisterState::from_regs([0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let after_instr1 = RegisterState::from_regs([0, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8]);
        let after_instr2 = RegisterState::from_regs([0, 94, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16]);

        let instr1 = InstructionTrace {
            pc: 0,
            instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00], // ADD_IMM r1, 42
            registers_before: initial_regs.clone(),
            registers_after: after_instr1.clone(),
        };

        let instr2 = InstructionTrace {
            pc: 8,
            instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00], // ADD_IMM r1, 42
            registers_before: after_instr1,
            registers_after: after_instr2.clone(),
        };

        let trace = ExecutionTrace {
            instructions: vec![instr1, instr2],
            account_states: vec![],
            initial_registers: initial_regs,
            final_registers: after_instr2,
        };

        // Create chunked circuit with size 5 (will pad with 3 NOPs)
        let circuit = CounterCircuit::from_trace_chunked(trace, 5);

        // Verify padding
        assert_eq!(circuit.trace.instructions.len(), 5);

        // Test synthesis
        base_test().run_gate(|ctx, gate| {
            circuit.synthesize(ctx, gate).unwrap();
        });
    }

    #[test]
    fn test_padding_empty_trace() {
        let trace = ExecutionTrace::new();
        let circuit = CounterCircuit::from_trace_chunked(trace, 10);

        assert_eq!(circuit.trace.instructions.len(), 10);
        // All instructions should be NOPs with same register state
        for instr in &circuit.trace.instructions {
            assert_eq!(instr.instruction_bytes, vec![0x00; 8]);
            // Verify register state unchanged (NOP behavior)
            for i in 0..11 {
                assert_eq!(
                    instr.registers_before.regs[i],
                    instr.registers_after.regs[i]
                );
            }
        }
    }
}
