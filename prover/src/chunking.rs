//! Chunking logic for recursive proving
//!
//! Splits execution traces into fixed-size chunks for proving.

use anyhow::Result;
use bpf_tracer::ExecutionTrace;

/// Split an execution trace into fixed-size chunks
///
/// Each chunk will contain up to `chunk_size` instructions.
/// The last chunk may have fewer instructions and will be padded during circuit creation.
///
/// # Example
/// ```ignore
/// let trace = ExecutionTrace { instructions: vec![...2500 instructions...], ... };
/// let chunks = split_trace_into_chunks(trace, 1000);
/// assert_eq!(chunks.len(), 3); // 1000 + 1000 + 500
/// ```
pub fn split_trace_into_chunks(trace: ExecutionTrace, chunk_size: usize) -> Result<Vec<ExecutionTrace>> {
    let total_instructions = trace.instructions.len();

    if total_instructions == 0 {
        // Empty trace - return single chunk
        return Ok(vec![trace]);
    }

    if total_instructions <= chunk_size {
        // Trace fits in single chunk
        return Ok(vec![trace]);
    }

    let num_chunks = (total_instructions + chunk_size - 1) / chunk_size;
    let mut chunks = Vec::with_capacity(num_chunks);

    for i in 0..num_chunks {
        let start_idx = i * chunk_size;
        let end_idx = ((i + 1) * chunk_size).min(total_instructions);

        let chunk_instructions = trace.instructions[start_idx..end_idx].to_vec();

        // Determine initial and final registers for this chunk
        let initial_registers = if i == 0 {
            trace.initial_registers.clone()
        } else {
            // Initial registers = final registers of previous chunk
            trace.instructions[start_idx - 1].registers_after.clone()
        };

        let final_registers = if end_idx == total_instructions {
            // Last chunk - use trace's final registers
            trace.final_registers.clone()
        } else {
            // Not last chunk - use last instruction's registers_after
            chunk_instructions.last().unwrap().registers_after.clone()
        };

        let chunk = ExecutionTrace {
            instructions: chunk_instructions,
            account_states: vec![], // TODO: Handle account states in chunks
            initial_registers,
            final_registers,
        };

        chunks.push(chunk);
    }

    tracing::debug!(
        "Split trace with {} instructions into {} chunks of size {}",
        total_instructions,
        num_chunks,
        chunk_size
    );

    Ok(chunks)
}

/// Information about a chunk proof
#[derive(Debug, Clone)]
pub struct ChunkProof {
    /// The proof bytes
    pub proof: Vec<u8>,
    /// Chunk index in the sequence
    pub index: usize,
    /// Initial register state for this chunk
    pub initial_registers: bpf_tracer::RegisterState,
    /// Final register state for this chunk
    pub final_registers: bpf_tracer::RegisterState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bpf_tracer::{InstructionTrace, RegisterState};

    fn create_dummy_instruction(pc: u64, reg_value: u64) -> InstructionTrace {
        let regs_before = RegisterState::from_regs([0, reg_value, 0, 0, 0, 0, 0, 0, 0, 0, 0, pc]);
        let regs_after = RegisterState::from_regs([0, reg_value + 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, pc + 8]);

        InstructionTrace {
            pc,
            instruction_bytes: vec![0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00], // ADD_IMM r1, 1
            registers_before: regs_before,
            registers_after: regs_after,
        }
    }

    #[test]
    fn test_empty_trace_single_chunk() {
        let trace = ExecutionTrace::new();
        let chunks = split_trace_into_chunks(trace, 1000).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].instructions.len(), 0);
    }

    #[test]
    fn test_small_trace_single_chunk() {
        let initial_regs = RegisterState::from_regs([0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let instrs = vec![
            create_dummy_instruction(0, 10),
            create_dummy_instruction(8, 11),
        ];
        let final_regs = instrs.last().unwrap().registers_after.clone();

        let trace = ExecutionTrace {
            instructions: instrs,
            account_states: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs,
        };

        let chunks = split_trace_into_chunks(trace, 1000).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].instructions.len(), 2);
    }

    #[test]
    fn test_split_into_multiple_chunks() {
        let initial_regs = RegisterState::from_regs([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Create 250 instructions
        let mut instrs = Vec::new();
        for i in 0..250 {
            instrs.push(create_dummy_instruction(i * 8, i));
        }
        let final_regs = instrs.last().unwrap().registers_after.clone();

        let trace = ExecutionTrace {
            instructions: instrs,
            account_states: vec![],
            initial_registers: initial_regs.clone(),
            final_registers: final_regs.clone(),
        };

        // Split into chunks of 100
        let chunks = split_trace_into_chunks(trace, 100).unwrap();

        assert_eq!(chunks.len(), 3); // 100 + 100 + 50
        assert_eq!(chunks[0].instructions.len(), 100);
        assert_eq!(chunks[1].instructions.len(), 100);
        assert_eq!(chunks[2].instructions.len(), 50);

        // Verify chunk boundaries
        assert_eq!(chunks[0].initial_registers.regs[1], 0);  // First chunk starts at 0
        assert_eq!(chunks[0].final_registers.regs[1], 100); // First chunk ends at 100

        assert_eq!(chunks[1].initial_registers.regs[1], 100); // Second chunk starts at 100
        assert_eq!(chunks[1].final_registers.regs[1], 200);   // Second chunk ends at 200

        assert_eq!(chunks[2].initial_registers.regs[1], 200); // Third chunk starts at 200
        assert_eq!(chunks[2].final_registers.regs[1], 250);   // Third chunk ends at 250
    }

    #[test]
    fn test_chunk_exactly_at_boundary() {
        let initial_regs = RegisterState::from_regs([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Create exactly 200 instructions (2 chunks of 100)
        let mut instrs = Vec::new();
        for i in 0..200 {
            instrs.push(create_dummy_instruction(i * 8, i));
        }
        let final_regs = instrs.last().unwrap().registers_after.clone();

        let trace = ExecutionTrace {
            instructions: instrs,
            account_states: vec![],
            initial_registers: initial_regs,
            final_registers: final_regs,
        };

        let chunks = split_trace_into_chunks(trace, 100).unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].instructions.len(), 100);
        assert_eq!(chunks[1].instructions.len(), 100);
    }
}
