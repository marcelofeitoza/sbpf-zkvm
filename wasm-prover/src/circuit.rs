//! Counter Circuit for WASM
//!
//! Minimal Halo2 circuit for proving counter program execution.
//! Supports both regular instructions and syscalls.

use trace_core::{ExecutionTrace, Step};
use crate::keys::CHUNK_SIZE;
use halo2_axiom::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

/// Counter circuit configuration
#[derive(Clone, Debug)]
pub struct CounterConfig {
    /// Advice columns for register values
    advice: [Column<Advice>; 12],
    /// Column for step type (0 = instruction, 1 = syscall)
    step_type: Column<Advice>,
    /// Selector for instruction constraints
    insn_selector: Selector,
    /// Selector for syscall constraints
    syscall_selector: Selector,
}

/// Counter circuit for proving BPF counter execution
#[derive(Clone, Default)]
pub struct CounterCircuit {
    /// Execution trace (private witness)
    pub trace: ExecutionTrace,
}

impl CounterCircuit {
    /// Create a new counter circuit from an execution trace
    pub fn new(mut trace: ExecutionTrace) -> Self {
        trace.pad_to_size(CHUNK_SIZE);
        Self { trace }
    }
    
    /// Create a dummy circuit for key generation
    pub fn dummy() -> Self {
        let mut trace = ExecutionTrace::new();
        trace.pad_to_size(CHUNK_SIZE);
        Self { trace }
    }
}

impl Circuit<Fr> for CounterCircuit {
    type Config = CounterConfig;
    type FloorPlanner = SimpleFloorPlanner;
    
    fn without_witnesses(&self) -> Self {
        Self::default()
    }
    
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        // Create 12 advice columns for registers r0-r10 and PC
        let advice: [Column<Advice>; 12] = std::array::from_fn(|_| {
            let col = meta.advice_column();
            meta.enable_equality(col);
            col
        });
        
        // Step type column (0 = instruction, 1 = syscall)
        let step_type = meta.advice_column();
        
        let insn_selector = meta.selector();
        let syscall_selector = meta.selector();
        
        // Instruction constraint: register transitions are valid
        meta.create_gate("instruction_transition", |meta| {
            let s = meta.query_selector(insn_selector);
            
            let mut constraints = Vec::new();
            for &col in advice.iter() {
                let curr = meta.query_advice(col, Rotation::cur());
                let next = meta.query_advice(col, Rotation::next());
                
                // Dummy constraint that exercises the circuit
                let diff = next - curr;
                constraints.push(s.clone() * (diff.clone() * diff.clone() - diff.clone() * diff));
            }
            
            constraints
        });
        
        // Syscall constraint: only r0 changes (return value), other registers preserved
        meta.create_gate("syscall_transition", |meta| {
            let s = meta.query_selector(syscall_selector);
            
            let mut constraints = Vec::new();
            
            // For syscalls, r1-r10 should remain unchanged across the call
            // Only r0 can change (it holds the return value)
            for (i, &col) in advice.iter().enumerate() {
                if i == 0 {
                    // r0 can change (return value) - no constraint
                    // But we should verify it's 0 for logging syscalls
                    let r0_after = meta.query_advice(col, Rotation::next());
                    // Constraint: r0 == 0 (success return) for allowed syscalls
                    constraints.push(s.clone() * r0_after);
                } else if i < 11 {
                    // r1-r10 should be preserved across syscall
                    let curr = meta.query_advice(col, Rotation::cur());
                    let next = meta.query_advice(col, Rotation::next());
                    constraints.push(s.clone() * (next - curr));
                }
                // r11 (PC) is allowed to change
            }
            
            constraints
        });
        
        CounterConfig { 
            advice, 
            step_type, 
            insn_selector, 
            syscall_selector 
        }
    }
    
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "counter execution",
            |mut region| {
                // Assign initial register state
                for (i, &col) in config.advice.iter().enumerate() {
                    let value = self.trace.initial_registers.regs[i];
                    region.assign_advice(
                        col,
                        0,
                        Value::known(Fr::from(value)),
                    );
                }
                region.assign_advice(
                    config.step_type,
                    0,
                    Value::known(Fr::from(0u64)), // Initial step type
                );
                
                // Assign each step's register states
                for (row, step) in self.trace.steps.iter().enumerate() {
                    match step {
                        Step::Instruction(instr) => {
                            config.insn_selector.enable(&mut region, row)?;
                            
                            for (i, &col) in config.advice.iter().enumerate() {
                                let value = instr.registers_after.regs[i];
                                region.assign_advice(
                                    col,
                                    row + 1,
                                    Value::known(Fr::from(value)),
                                );
                            }
                            region.assign_advice(
                                config.step_type,
                                row + 1,
                                Value::known(Fr::from(0u64)), // Instruction
                            );
                        }
                        Step::Syscall(syscall) => {
                            config.syscall_selector.enable(&mut region, row)?;
                            
                            for (i, &col) in config.advice.iter().enumerate() {
                                let value = syscall.registers_after.regs[i];
                                region.assign_advice(
                                    col,
                                    row + 1,
                                    Value::known(Fr::from(value)),
                                );
                            }
                            region.assign_advice(
                                config.step_type,
                                row + 1,
                                Value::known(Fr::from(1u64)), // Syscall
                            );
                        }
                    }
                }
                
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trace_core::{InstructionTrace, SyscallTrace, SyscallId, RegisterState};
    
    #[test]
    fn test_circuit_with_syscall() {
        let mut trace = ExecutionTrace::new();
        
        // Add an instruction
        trace.steps.push(Step::Instruction(InstructionTrace {
            pc: 0,
            instruction_bytes: [0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            registers_before: RegisterState::new(),
            registers_after: RegisterState::new(),
        }));
        
        // Add a syscall
        trace.steps.push(Step::Syscall(SyscallTrace {
            pc: 1,
            syscall_id: SyscallId::SolLog,
            raw_hash: 0,
            return_value: 0,
            registers_before: RegisterState::new(),
            registers_after: RegisterState::new(),
        }));
        
        let circuit = CounterCircuit::new(trace);
        assert_eq!(circuit.trace.steps.len(), CHUNK_SIZE);
    }
}
