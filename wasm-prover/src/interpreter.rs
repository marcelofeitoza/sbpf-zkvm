//! Minimal BPF Interpreter
//!
//! A pure Rust BPF interpreter that supports only the instructions
//! needed for the counter program. No system dependencies.
//!
//! Supported instructions:
//! - MOV64_IMM (0xb7): Move immediate to register
//! - MOV64_REG (0xbf): Move register to register  
//! - ADD64_IMM (0x07): Add immediate to register
//! - ADD64_REG (0x0f): Add register to register
//! - LDW (0x61): Load word from memory
//! - STW (0x63): Store word to memory
//! - LDXDW (0x79): Load double word from memory
//! - STXDW (0x7b): Store double word to memory
//! - EXIT (0x95): Exit program

use crate::trace::{ExecutionTrace, InstructionTrace, RegisterState};

/// BPF instruction opcodes
mod opcodes {
    pub const MOV64_IMM: u8 = 0xb7;
    pub const MOV64_REG: u8 = 0xbf;
    pub const ADD64_IMM: u8 = 0x07;
    pub const ADD64_REG: u8 = 0x0f;
    pub const LDW: u8 = 0x61;       // Load word (32-bit)
    pub const STW: u8 = 0x63;       // Store word (32-bit)
    pub const LDXDW: u8 = 0x79;     // Load double word (64-bit)
    pub const STXDW: u8 = 0x7b;     // Store double word (64-bit)
    pub const EXIT: u8 = 0x95;
}

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
    /// Registers r0-r10 + r11 (PC)
    registers: [u64; 12],
    /// Memory
    memory: Vec<u8>,
    /// Program bytecode
    program: Vec<u8>,
    /// Program counter (instruction index)
    pc: usize,
    /// Instruction traces
    traces: Vec<InstructionTrace>,
}

impl BpfVm {
    fn new(program: &[u8], input_data: &[u8]) -> Self {
        let mut memory = vec![0u8; MEMORY_SIZE];
        
        // Copy input data to memory
        let input_offset = 0;
        memory[input_offset..input_offset + input_data.len()].copy_from_slice(input_data);
        
        let mut registers = [0u64; 12];
        // r1 points to input data (using virtual address)
        registers[1] = INPUT_START;
        // r10 is frame pointer
        registers[10] = (MEMORY_SIZE - 1024) as u64;
        
        Self {
            registers,
            memory,
            program: program.to_vec(),
            pc: 0,
            traces: Vec::new(),
        }
    }
    
    /// Translate virtual address to memory offset
    fn translate_addr(&self, vaddr: u64) -> Option<usize> {
        if vaddr >= INPUT_START && vaddr < INPUT_START + MEMORY_SIZE as u64 {
            Some((vaddr - INPUT_START) as usize)
        } else if vaddr < MEMORY_SIZE as u64 {
            Some(vaddr as usize)
        } else {
            None
        }
    }
    
    /// Execute the program and return the trace
    fn execute(&mut self) -> Result<ExecutionTrace, String> {
        let initial_registers = RegisterState::from_array(self.registers);
        
        loop {
            if self.pc * 8 >= self.program.len() {
                return Err("Program counter out of bounds".into());
            }
            
            let insn_offset = self.pc * 8;
            
            // Copy instruction bytes to avoid borrow issues
            let insn_bytes: Vec<u8> = self.program[insn_offset..insn_offset + 8].to_vec();
            
            let opcode = insn_bytes[0];
            let dst = (insn_bytes[1] & 0x0f) as usize;
            let src = ((insn_bytes[1] >> 4) & 0x0f) as usize;
            let offset = i16::from_le_bytes([insn_bytes[2], insn_bytes[3]]);
            let imm = i32::from_le_bytes([insn_bytes[4], insn_bytes[5], insn_bytes[6], insn_bytes[7]]);
            
            // Capture state before execution
            let regs_before = RegisterState::from_array(self.registers);
            self.registers[11] = self.pc as u64; // Update PC in registers
            
            // Execute instruction
            let should_exit = self.execute_instruction(opcode, dst, src, offset, imm)?;
            
            // Capture state after execution
            self.registers[11] = (self.pc + 1) as u64; // PC after instruction
            let regs_after = RegisterState::from_array(self.registers);
            
            // Record trace
            self.traces.push(InstructionTrace {
                pc: (self.pc * 8) as u64,
                instruction_bytes: insn_bytes,
                registers_before: regs_before,
                registers_after: regs_after.clone(),
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
            opcodes::LDW => {
                let addr = self.registers[src].wrapping_add(offset as i64 as u64);
                let mem_offset = self.translate_addr(addr)
                    .ok_or_else(|| format!("Invalid memory address: 0x{:x}", addr))?;
                
                if mem_offset + 4 > self.memory.len() {
                    return Err(format!("Memory read out of bounds at 0x{:x}", addr));
                }
                
                let value = u32::from_le_bytes([
                    self.memory[mem_offset],
                    self.memory[mem_offset + 1],
                    self.memory[mem_offset + 2],
                    self.memory[mem_offset + 3],
                ]);
                self.registers[dst] = value as u64;
            }
            opcodes::STW => {
                let addr = self.registers[dst].wrapping_add(offset as i64 as u64);
                let mem_offset = self.translate_addr(addr)
                    .ok_or_else(|| format!("Invalid memory address: 0x{:x}", addr))?;
                
                if mem_offset + 4 > self.memory.len() {
                    return Err(format!("Memory write out of bounds at 0x{:x}", addr));
                }
                
                let value = self.registers[src] as u32;
                let bytes = value.to_le_bytes();
                self.memory[mem_offset..mem_offset + 4].copy_from_slice(&bytes);
            }
            opcodes::LDXDW => {
                let addr = self.registers[src].wrapping_add(offset as i64 as u64);
                let mem_offset = self.translate_addr(addr)
                    .ok_or_else(|| format!("Invalid memory address: 0x{:x}", addr))?;
                
                if mem_offset + 8 > self.memory.len() {
                    return Err(format!("Memory read out of bounds at 0x{:x}", addr));
                }
                
                let value = u64::from_le_bytes([
                    self.memory[mem_offset],
                    self.memory[mem_offset + 1],
                    self.memory[mem_offset + 2],
                    self.memory[mem_offset + 3],
                    self.memory[mem_offset + 4],
                    self.memory[mem_offset + 5],
                    self.memory[mem_offset + 6],
                    self.memory[mem_offset + 7],
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
///
/// # Arguments
/// * `initial_value` - The initial counter value
///
/// # Returns
/// * ExecutionTrace containing all instruction traces
pub fn execute_counter(initial_value: u64) -> Result<ExecutionTrace, String> {
    tracing::debug!("Executing counter program with initial_value={}", initial_value);
    
    // Prepare input data: just the initial counter value as u64
    let input_data = initial_value.to_le_bytes();
    
    // Create VM and execute
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
        
        // Should have 5 instructions
        assert_eq!(trace.instructions.len(), 5);
        
        // r0 should be 0 (success)
        assert_eq!(trace.final_registers.regs[0], 0);
        
        // r2 should contain incremented value (43)
        assert_eq!(trace.final_registers.regs[2], 43);
    }
    
    #[test]
    fn test_execute_counter_overflow() {
        let trace = execute_counter(u64::MAX).expect("Should execute");
        
        // Should wrap around to 0
        assert_eq!(trace.final_registers.regs[2], 0);
    }
}

