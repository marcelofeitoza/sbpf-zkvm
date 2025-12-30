//! Minimal BPF Interpreter (Toy - for testing only)
//!
//! A pure Rust BPF interpreter that supports only the instructions
//! needed for the counter program. No system dependencies.
//!
//! This is behind the `toy-interpreter` feature flag.
//! For real traces, use trace-exporter with the actual Solana VM.

use trace_core::{ExecutionTrace, InstructionTrace, RegisterState, opcodes};

/// Hardcoded counter program bytecode
/// 
/// This is a simplified counter that:
/// 1. Reads a u64 from memory at address in r1
/// 2. Increments it by 1
/// 3. Writes it back
/// 4. Returns 0 (success)
const COUNTER_BYTECODE: &[u8] = &[
    // ldxdw r2, [r1+0]    - Load counter value from memory
    0x79, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // add64 r2, 1         - Increment by 1
    0x07, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    // stxdw [r1+0], r2    - Store back to memory
    0x7b, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // mov64 r0, 0         - Return success
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // exit
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Memory size for the interpreter (64KB)
const MEMORY_SIZE: usize = 65536;

/// Input memory region start
const INPUT_START: u64 = 0x400000000;

/// BPF Virtual Machine state
struct BpfVm {
    registers: [u64; 12],
    memory: Vec<u8>,
    program: Vec<u8>,
    pc: usize,
    traces: Vec<InstructionTrace>,
}

impl BpfVm {
    fn new(program: &[u8], input_data: &[u8]) -> Self {
        let mut memory = vec![0u8; MEMORY_SIZE];
        let input_offset = 0;
        memory[input_offset..input_offset + input_data.len()].copy_from_slice(input_data);
        
        let mut registers = [0u64; 12];
        registers[1] = INPUT_START;
        registers[10] = (MEMORY_SIZE - 1024) as u64;
        
        Self {
            registers,
            memory,
            program: program.to_vec(),
            pc: 0,
            traces: Vec::new(),
        }
    }
    
    fn translate_addr(&self, vaddr: u64) -> Option<usize> {
        if vaddr >= INPUT_START && vaddr < INPUT_START + MEMORY_SIZE as u64 {
            Some((vaddr - INPUT_START) as usize)
        } else if vaddr < MEMORY_SIZE as u64 {
            Some(vaddr as usize)
        } else {
            None
        }
    }
    
    fn execute(&mut self) -> Result<ExecutionTrace, String> {
        let initial_registers = RegisterState::from_array(self.registers);
        
        loop {
            if self.pc * 8 >= self.program.len() {
                return Err("Program counter out of bounds".into());
            }
            
            let insn_offset = self.pc * 8;
            let mut instruction_bytes = [0u8; 8];
            instruction_bytes.copy_from_slice(&self.program[insn_offset..insn_offset + 8]);
            
            let opcode = instruction_bytes[0];
            let dst = (instruction_bytes[1] & 0x0f) as usize;
            let src = ((instruction_bytes[1] >> 4) & 0x0f) as usize;
            let offset = i16::from_le_bytes([instruction_bytes[2], instruction_bytes[3]]);
            let imm = i32::from_le_bytes([instruction_bytes[4], instruction_bytes[5], instruction_bytes[6], instruction_bytes[7]]);
            
            let regs_before = RegisterState::from_array(self.registers);
            self.registers[11] = self.pc as u64;
            
            let should_exit = self.execute_instruction(opcode, dst, src, offset, imm)?;
            
            self.registers[11] = (self.pc + 1) as u64;
            let regs_after = RegisterState::from_array(self.registers);
            
            self.traces.push(InstructionTrace {
                pc: (self.pc * 8) as u64,
                instruction_bytes,
                registers_before: regs_before,
                registers_after: regs_after,
            });
            
            self.pc += 1;
            
            if should_exit {
                return Ok(ExecutionTrace {
                    instructions: std::mem::take(&mut self.traces),
                    initial_registers,
                    final_registers: regs_after,
                });
            }
        }
    }
    
    fn execute_instruction(
        &mut self,
        opcode: u8,
        dst: usize,
        src: usize,
        offset: i16,
        imm: i32,
    ) -> Result<bool, String> {
        match opcode {
            opcodes::MOV64_IMM => {
                self.registers[dst] = imm as i64 as u64;
            }
            opcodes::MOV64_REG => {
                self.registers[dst] = self.registers[src];
            }
            opcodes::ADD64_IMM => {
                self.registers[dst] = self.registers[dst].wrapping_add(imm as i64 as u64);
            }
            opcodes::ADD64_REG => {
                self.registers[dst] = self.registers[dst].wrapping_add(self.registers[src]);
            }
            opcodes::LDXDW => {
                let addr = self.registers[src].wrapping_add(offset as i64 as u64);
                let mem_offset = self.translate_addr(addr)
                    .ok_or_else(|| format!("Invalid memory address: 0x{:x}", addr))?;
                
                if mem_offset + 8 > self.memory.len() {
                    return Err(format!("Memory read out of bounds at 0x{:x}", addr));
                }
                
                let value = u64::from_le_bytes([
                    self.memory[mem_offset], self.memory[mem_offset + 1],
                    self.memory[mem_offset + 2], self.memory[mem_offset + 3],
                    self.memory[mem_offset + 4], self.memory[mem_offset + 5],
                    self.memory[mem_offset + 6], self.memory[mem_offset + 7],
                ]);
                self.registers[dst] = value;
            }
            opcodes::STXDW => {
                let addr = self.registers[dst].wrapping_add(offset as i64 as u64);
                let mem_offset = self.translate_addr(addr)
                    .ok_or_else(|| format!("Invalid memory address: 0x{:x}", addr))?;
                
                if mem_offset + 8 > self.memory.len() {
                    return Err(format!("Memory write out of bounds at 0x{:x}", addr));
                }
                
                let value = self.registers[src];
                let bytes = value.to_le_bytes();
                self.memory[mem_offset..mem_offset + 8].copy_from_slice(&bytes);
            }
            opcodes::EXIT => {
                return Ok(true);
            }
            _ => {
                return Err(format!("Unsupported opcode: 0x{:02x}", opcode));
            }
        }
        
        Ok(false)
    }
}

/// Execute the counter program with the given initial value
pub fn execute_counter(initial_value: u64) -> Result<ExecutionTrace, String> {
    tracing::debug!("Executing counter program with initial_value={}", initial_value);
    
    let input_data = initial_value.to_le_bytes();
    let mut vm = BpfVm::new(COUNTER_BYTECODE, &input_data);
    let trace = vm.execute()?;
    
    tracing::debug!(
        "Execution complete: {} instructions, final r0={}",
        trace.instructions.len(),
        trace.final_registers.regs[0]
    );
    
    Ok(trace)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_execute_counter() {
        let trace = execute_counter(42).expect("Should execute");
        assert_eq!(trace.instructions.len(), 5);
        assert_eq!(trace.final_registers.regs[0], 0);
        assert_eq!(trace.final_registers.regs[2], 43);
    }
}
