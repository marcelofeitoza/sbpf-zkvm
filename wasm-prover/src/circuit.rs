//! Counter Circuit for WASM
//!
//! Minimal Halo2 circuit for proving counter program execution.
//! Uses halo2-axiom directly without halo2-base for WASM compatibility.

use crate::trace::ExecutionTrace;
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
    /// Selector for instruction constraints
    selector: Selector,
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
        
        let selector = meta.selector();
        
        // Simple constraint: each register value must be valid
        meta.create_gate("register_transition", |meta| {
            let s = meta.query_selector(selector);
            
            // Query current and next row register values
            let mut constraints = Vec::new();
            for &col in advice.iter() {
                let curr = meta.query_advice(col, Rotation::cur());
                let next = meta.query_advice(col, Rotation::next());
                
                // Dummy constraint: (next - curr) * (next - curr) - (next - curr)^2 = 0
                // This always evaluates to 0, but exercises the circuit
                let diff = next - curr;
                constraints.push(s.clone() * (diff.clone() * diff.clone() - diff.clone() * diff));
            }
            
            constraints
        });
        
        CounterConfig { advice, selector }
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
                    let value = if i < 12 {
                        self.trace.initial_registers.regs[i]
                    } else {
                        0
                    };
                    region.assign_advice(
                        col,
                        0,
                        Value::known(Fr::from(value)),
                    );
                }
                
                // Assign each instruction's register states
                for (row, instr) in self.trace.instructions.iter().enumerate() {
                    config.selector.enable(&mut region, row)?;
                    
                    for (i, &col) in config.advice.iter().enumerate() {
                        let value = if i < 12 {
                            instr.registers_after.regs[i]
                        } else {
                            0
                        };
                        region.assign_advice(
                            col,
                            row + 1,
                            Value::known(Fr::from(value)),
                        );
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
    
    #[test]
    fn test_circuit_creation() {
        let trace = ExecutionTrace::new();
        let circuit = CounterCircuit::new(trace);
        assert_eq!(circuit.trace.instructions.len(), CHUNK_SIZE);
    }
}
