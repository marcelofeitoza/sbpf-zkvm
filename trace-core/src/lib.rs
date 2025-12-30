//! Trace Core - Shared trace types for sbpf-zkvm
//!
//! This crate provides trace structures that are compatible with both
//! native Rust and WebAssembly environments. No dependencies on
//! Solana-specific crates to ensure WASM compatibility.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use alloc::format;
use serde::{Deserialize, Serialize};

/// Magic bytes for trace file format
pub const TRACE_MAGIC: &[u8; 8] = b"SBPFZK02"; // Version 2 with syscall support

/// Current trace format version
pub const TRACE_VERSION: u32 = 2;

/// BPF opcodes supported by the zkVM circuit
pub mod opcodes {
    // ALU64 operations with immediate
    pub const ADD64_IMM: u8 = 0x07;
    pub const SUB64_IMM: u8 = 0x17;
    pub const MUL64_IMM: u8 = 0x27;
    pub const DIV64_IMM: u8 = 0x37;
    pub const OR64_IMM: u8 = 0x47;
    pub const AND64_IMM: u8 = 0x57;
    pub const LSH64_IMM: u8 = 0x67;  // Left shift
    pub const RSH64_IMM: u8 = 0x77;  // Right shift (logical)
    pub const NEG64: u8 = 0x87;
    pub const MOD64_IMM: u8 = 0x97;
    pub const XOR64_IMM: u8 = 0xa7;
    pub const MOV64_IMM: u8 = 0xb7;
    pub const ARSH64_IMM: u8 = 0xc7; // Arithmetic right shift
    
    // ALU64 operations with register
    pub const ADD64_REG: u8 = 0x0f;
    pub const SUB64_REG: u8 = 0x1f;
    pub const MUL64_REG: u8 = 0x2f;
    pub const DIV64_REG: u8 = 0x3f;
    pub const OR64_REG: u8 = 0x4f;
    pub const AND64_REG: u8 = 0x5f;
    pub const LSH64_REG: u8 = 0x6f;
    pub const RSH64_REG: u8 = 0x7f;
    pub const MOD64_REG: u8 = 0x9f;
    pub const XOR64_REG: u8 = 0xaf;
    pub const MOV64_REG: u8 = 0xbf;
    pub const ARSH64_REG: u8 = 0xcf;
    
    // ALU32 operations with immediate
    pub const ADD32_IMM: u8 = 0x04;
    pub const SUB32_IMM: u8 = 0x14;
    pub const MUL32_IMM: u8 = 0x24;
    pub const DIV32_IMM: u8 = 0x34;
    pub const OR32_IMM: u8 = 0x44;
    pub const AND32_IMM: u8 = 0x54;
    pub const LSH32_IMM: u8 = 0x64;
    pub const RSH32_IMM: u8 = 0x74;
    pub const NEG32: u8 = 0x84;
    pub const MOD32_IMM: u8 = 0x94;
    pub const XOR32_IMM: u8 = 0xa4;
    pub const MOV32_IMM: u8 = 0xb4;
    pub const ARSH32_IMM: u8 = 0xc4;
    
    // ALU32 operations with register
    pub const ADD32_REG: u8 = 0x0c;
    pub const SUB32_REG: u8 = 0x1c;
    pub const MUL32_REG: u8 = 0x2c;
    pub const DIV32_REG: u8 = 0x3c;
    pub const OR32_REG: u8 = 0x4c;
    pub const AND32_REG: u8 = 0x5c;
    pub const LSH32_REG: u8 = 0x6c;
    pub const RSH32_REG: u8 = 0x7c;
    pub const MOD32_REG: u8 = 0x9c;
    pub const XOR32_REG: u8 = 0xac;
    pub const MOV32_REG: u8 = 0xbc;
    pub const ARSH32_REG: u8 = 0xcc;
    
    // Memory operations
    pub const LDDW: u8 = 0x18;      // Load double word immediate (wide instruction)
    pub const LDW: u8 = 0x61;       // Load word (32-bit) from memory
    pub const LDH: u8 = 0x69;       // Load half-word (16-bit)
    pub const LDB: u8 = 0x71;       // Load byte
    pub const LDXDW: u8 = 0x79;     // Load double word (64-bit) from memory
    pub const STW: u8 = 0x63;       // Store word (32-bit)
    pub const STH: u8 = 0x6b;       // Store half-word (16-bit)
    pub const STB: u8 = 0x73;       // Store byte
    pub const STXDW: u8 = 0x7b;     // Store double word (64-bit)
    pub const STW_IMM: u8 = 0x62;   // Store word immediate
    pub const STH_IMM: u8 = 0x6a;   // Store half-word immediate
    pub const STB_IMM: u8 = 0x72;   // Store byte immediate
    pub const STDW_IMM: u8 = 0x7a;  // Store double word immediate
    
    // Jumps
    pub const JA: u8 = 0x05;        // Jump always
    pub const JEQ_IMM: u8 = 0x15;   // Jump if equal (imm)
    pub const JGT_IMM: u8 = 0x25;   // Jump if greater than (imm)
    pub const JGE_IMM: u8 = 0x35;   // Jump if greater or equal (imm)
    pub const JSET_IMM: u8 = 0x45;  // Jump if set (imm)
    pub const JNE_IMM: u8 = 0x55;   // Jump if not equal (imm)
    pub const JSGT_IMM: u8 = 0x65;  // Jump if signed greater than (imm)
    pub const JSGE_IMM: u8 = 0x75;  // Jump if signed greater or equal (imm)
    pub const JLT_IMM: u8 = 0xa5;   // Jump if less than (imm)
    pub const JLE_IMM: u8 = 0xb5;   // Jump if less or equal (imm)
    pub const JSLT_IMM: u8 = 0xc5;  // Jump if signed less than (imm)
    pub const JSLE_IMM: u8 = 0xd5;  // Jump if signed less or equal (imm)
    
    pub const JEQ_REG: u8 = 0x1d;   // Jump if equal (reg)
    pub const JGT_REG: u8 = 0x2d;   // Jump if greater than (reg)
    pub const JGE_REG: u8 = 0x3d;   // Jump if greater or equal (reg)
    pub const JSET_REG: u8 = 0x4d;  // Jump if set (reg)
    pub const JNE_REG: u8 = 0x5d;   // Jump if not equal (reg)
    pub const JSGT_REG: u8 = 0x6d;  // Jump if signed greater than (reg)
    pub const JSGE_REG: u8 = 0x7d;  // Jump if signed greater or equal (reg)
    pub const JLT_REG: u8 = 0xad;   // Jump if less than (reg)
    pub const JLE_REG: u8 = 0xbd;   // Jump if less or equal (reg)
    pub const JSLT_REG: u8 = 0xcd;  // Jump if signed less than (reg)
    pub const JSLE_REG: u8 = 0xdd;  // Jump if signed less or equal (reg)
    
    // Call and exit
    pub const CALL_IMM: u8 = 0x85;  // Call (syscall)
    pub const CALL_REG: u8 = 0x8d;  // Call register (internal)
    pub const EXIT: u8 = 0x95;
    
    // Byteswap
    pub const LE: u8 = 0xd4;        // Little endian conversion
    pub const BE: u8 = 0xdc;        // Big endian conversion
    
    /// Check if opcode is a syscall
    pub fn is_syscall(opcode: u8) -> bool {
        opcode == CALL_IMM
    }
    
    /// Check if opcode is supported by the zkVM circuit (excluding syscalls)
    pub fn is_supported_insn(opcode: u8) -> bool {
        matches!(
            opcode,
            // ALU64
            ADD64_IMM | SUB64_IMM | MUL64_IMM | DIV64_IMM | OR64_IMM | AND64_IMM |
            LSH64_IMM | RSH64_IMM | NEG64 | MOD64_IMM | XOR64_IMM | MOV64_IMM | ARSH64_IMM |
            ADD64_REG | SUB64_REG | MUL64_REG | DIV64_REG | OR64_REG | AND64_REG |
            LSH64_REG | RSH64_REG | MOD64_REG | XOR64_REG | MOV64_REG | ARSH64_REG |
            // ALU32
            ADD32_IMM | SUB32_IMM | MUL32_IMM | DIV32_IMM | OR32_IMM | AND32_IMM |
            LSH32_IMM | RSH32_IMM | NEG32 | MOD32_IMM | XOR32_IMM | MOV32_IMM | ARSH32_IMM |
            ADD32_REG | SUB32_REG | MUL32_REG | DIV32_REG | OR32_REG | AND32_REG |
            LSH32_REG | RSH32_REG | MOD32_REG | XOR32_REG | MOV32_REG | ARSH32_REG |
            // Memory
            LDDW | LDW | LDH | LDB | LDXDW | STW | STH | STB | STXDW |
            STW_IMM | STH_IMM | STB_IMM | STDW_IMM |
            // Jumps
            JA | JEQ_IMM | JGT_IMM | JGE_IMM | JSET_IMM | JNE_IMM | JSGT_IMM | JSGE_IMM |
            JLT_IMM | JLE_IMM | JSLT_IMM | JSLE_IMM |
            JEQ_REG | JGT_REG | JGE_REG | JSET_REG | JNE_REG | JSGT_REG | JSGE_REG |
            JLT_REG | JLE_REG | JSLT_REG | JSLE_REG |
            // Call and exit
            CALL_REG | EXIT |
            // Byteswap
            LE | BE |
            // NOP (0x00 padding)
            0x00
        )
    }
    
    /// Get opcode name for debugging
    pub fn name(opcode: u8) -> &'static str {
        match opcode {
            ADD64_IMM => "ADD64_IMM",
            ADD64_REG => "ADD64_REG",
            SUB64_IMM => "SUB64_IMM",
            SUB64_REG => "SUB64_REG",
            MUL64_IMM => "MUL64_IMM",
            MUL64_REG => "MUL64_REG",
            DIV64_IMM => "DIV64_IMM",
            DIV64_REG => "DIV64_REG",
            OR64_IMM => "OR64_IMM",
            OR64_REG => "OR64_REG",
            AND64_IMM => "AND64_IMM",
            AND64_REG => "AND64_REG",
            LSH64_IMM => "LSH64_IMM",
            LSH64_REG => "LSH64_REG",
            RSH64_IMM => "RSH64_IMM",
            RSH64_REG => "RSH64_REG",
            NEG64 => "NEG64",
            MOD64_IMM => "MOD64_IMM",
            MOD64_REG => "MOD64_REG",
            XOR64_IMM => "XOR64_IMM",
            XOR64_REG => "XOR64_REG",
            MOV64_IMM => "MOV64_IMM",
            MOV64_REG => "MOV64_REG",
            ARSH64_IMM => "ARSH64_IMM",
            ARSH64_REG => "ARSH64_REG",
            LSH32_IMM => "LSH32_IMM",
            MOV32_IMM => "MOV32_IMM",
            MOV32_REG => "MOV32_REG",
            LDW => "LDW",
            STW => "STW",
            LDXDW => "LDXDW",
            STXDW => "STXDW",
            LDDW => "LDDW",
            JA => "JA",
            JEQ_IMM => "JEQ_IMM",
            JNE_IMM => "JNE_IMM",
            CALL_IMM => "CALL_IMM (syscall)",
            CALL_REG => "CALL_REG",
            EXIT => "EXIT",
            0x00 => "NOP",
            _ => "UNKNOWN",
        }
    }
}

// ============================================================================
// Syscall Policy - Strict whitelist and effect constraints
// ============================================================================

/// Expected effects of a syscall for zkVM verification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallEffects {
    /// Expected return value (None means any return value is valid)
    pub expected_return: Option<u64>,
    /// Whether registers r1-r5 (args) may change
    pub args_may_change: bool,
    /// Whether this syscall modifies memory
    pub modifies_memory: bool,
}

impl SyscallEffects {
    /// Logging syscalls: return 0, no side effects
    pub const LOG: Self = Self {
        expected_return: Some(0),
        args_may_change: false,
        modifies_memory: false,
    };
    
    /// Memory syscalls: any return, args may be modified, modifies memory
    /// Note: Memory effects are NOT verified by the circuit
    pub const MEMORY: Self = Self {
        expected_return: None, // Memory syscalls may return various values
        args_may_change: true,
        modifies_memory: true,
    };
    
    /// Memory compare: any return, args may change, memory effects
    pub const MEMCMP: Self = Self {
        expected_return: None,
        args_may_change: true,
        modifies_memory: true,
    };
}

/// Syscall policy for validation and circuit constraints
#[derive(Debug, Clone)]
pub struct SyscallPolicy {
    /// Allow unknown syscalls (debug mode only)
    pub allow_unknown: bool,
}

impl Default for SyscallPolicy {
    fn default() -> Self {
        Self::strict()
    }
}

impl SyscallPolicy {
    /// Strict policy: only whitelisted syscalls allowed
    pub fn strict() -> Self {
        Self { allow_unknown: false }
    }
    
    /// Debug policy: allow unknown syscalls (NOT for production)
    pub fn debug() -> Self {
        Self { allow_unknown: true }
    }
    
    /// Check if a syscall is allowed under this policy
    pub fn is_allowed(&self, id: &SyscallId) -> bool {
        match id {
            // Logging syscalls - fully verified (no side effects)
            SyscallId::SolLog |
            SyscallId::SolLog64 |
            SyscallId::SolLogPubkey |
            SyscallId::SolLogComputeUnits => true,
            
            // Memory syscalls - allowed but memory effects NOT verified
            // We only check return value and register preservation
            // This is safe for proving trace consistency but NOT memory correctness
            SyscallId::SolMemcpy |
            SyscallId::SolMemset |
            SyscallId::SolMemmove |
            SyscallId::SolMemcmp => true,
            
            // Abort - never allowed (indicates error)
            SyscallId::Abort => false,
            
            // Unknown syscalls - only in debug mode
            SyscallId::Unknown(_) => self.allow_unknown,
        }
    }
    
    /// Get expected effects for a syscall
    pub fn effects(&self, id: &SyscallId) -> Option<SyscallEffects> {
        match id {
            SyscallId::SolLog |
            SyscallId::SolLog64 |
            SyscallId::SolLogPubkey |
            SyscallId::SolLogComputeUnits => Some(SyscallEffects::LOG),
            
            SyscallId::SolMemcpy |
            SyscallId::SolMemset |
            SyscallId::SolMemmove => Some(SyscallEffects::MEMORY),
            
            SyscallId::SolMemcmp => Some(SyscallEffects::MEMCMP),
            
            SyscallId::Abort => None,
            
            // Unknown syscalls in debug mode: assume logging behavior
            SyscallId::Unknown(_) if self.allow_unknown => Some(SyscallEffects::LOG),
            SyscallId::Unknown(_) => None,
        }
    }
    
    /// Get list of whitelisted syscall names (logging - fully verified)
    pub fn logging_syscalls() -> &'static [&'static str] {
        &["sol_log_", "sol_log_64_", "sol_log_pubkey_", "sol_log_compute_units_"]
    }
    
    /// Get list of memory syscalls (allowed but memory effects NOT verified)
    pub fn memory_syscalls() -> &'static [&'static str] {
        &["sol_memcpy_", "sol_memset_", "sol_memmove_", "sol_memcmp_"]
    }
    
    /// Get all allowed syscall names
    pub fn all_allowed() -> &'static [&'static str] {
        &[
            "sol_log_", "sol_log_64_", "sol_log_pubkey_", "sol_log_compute_units_",
            "sol_memcpy_", "sol_memset_", "sol_memmove_", "sol_memcmp_"
        ]
    }
}

/// Syscall identifiers supported by zkVM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallId {
    /// sol_log_ - Log a string message
    SolLog,
    /// sol_log_64_ - Log 5 u64 values
    SolLog64,
    /// sol_log_pubkey_ - Log a pubkey
    SolLogPubkey,
    /// sol_log_compute_units_ - Log remaining compute units
    SolLogComputeUnits,
    /// sol_memcpy_ - Memory copy
    SolMemcpy,
    /// sol_memset_ - Memory set
    SolMemset,
    /// sol_memmove_ - Memory move
    SolMemmove,
    /// sol_memcmp_ - Memory compare
    SolMemcmp,
    /// abort - Program abort
    Abort,
    /// Unknown syscall (with raw hash for error reporting)
    Unknown(u32),
}

impl SyscallId {
    /// Decode syscall ID from the imm field of CALL_IMM instruction
    /// The hash is computed by solana-sbpf using murmur3 on the syscall name
    /// Returns None if the hash doesn't match any known syscall (internal function call)
    pub fn from_imm(imm: i32) -> Option<Self> {
        let hash = imm as u32;
        // These are the actual murmur3 hashes used by solana-sbpf
        // Computed from the syscall names registered in bpf-tracer/src/syscalls.rs
        // Note: Hash values determined empirically by observing traces
        match hash {
            // Logging syscalls
            0x56ffab99 => Some(SyscallId::SolLog),      // sol_log_
            0x5fdcde31 => Some(SyscallId::SolLog64),    // sol_log_64_
            
            // Memory syscalls
            0x717cc4a3 => Some(SyscallId::SolMemcpy),   // sol_memcpy_
            0xa20adc3a => Some(SyscallId::SolMemset),   // sol_memset_
            0xbbb11f89 => Some(SyscallId::SolMemmove),  // sol_memmove_
            0xce18c592 => Some(SyscallId::SolMemcmp),   // sol_memcmp_
            
            // Not a syscall - internal function call or unknown
            _ => None,
        }
    }
    
    /// Check if a hash corresponds to a known syscall
    pub fn is_known_syscall_hash(hash: u32) -> bool {
        matches!(hash,
            0x56ffab99 | 0x5fdcde31 |  // logging
            0x717cc4a3 | 0xa20adc3a | 0xbbb11f89 | 0xce18c592 |  // memory
            0x78fdeb99  // abort
        )
    }
    
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            SyscallId::SolLog => "sol_log_",
            SyscallId::SolLog64 => "sol_log_64_",
            SyscallId::SolLogPubkey => "sol_log_pubkey_",
            SyscallId::SolLogComputeUnits => "sol_log_compute_units_",
            SyscallId::SolMemcpy => "sol_memcpy_",
            SyscallId::SolMemset => "sol_memset_",
            SyscallId::SolMemmove => "sol_memmove_",
            SyscallId::SolMemcmp => "sol_memcmp_",
            SyscallId::Abort => "abort",
            SyscallId::Unknown(_) => "unknown",
        }
    }
    
    /// Check if this is a whitelisted logging syscall
    pub fn is_whitelisted_log(&self) -> bool {
        matches!(self,
            SyscallId::SolLog |
            SyscallId::SolLog64 |
            SyscallId::SolLogPubkey |
            SyscallId::SolLogComputeUnits
        )
    }
    
    /// Check if this is an unknown syscall
    pub fn is_unknown(&self) -> bool {
        matches!(self, SyscallId::Unknown(_))
    }
    
    /// Convert to u32 for serialization
    pub fn to_u32(&self) -> u32 {
        match self {
            SyscallId::SolLog => 1,
            SyscallId::SolLog64 => 2,
            SyscallId::SolLogPubkey => 3,
            SyscallId::SolLogComputeUnits => 4,
            SyscallId::SolMemcpy => 5,
            SyscallId::SolMemset => 6,
            SyscallId::SolMemmove => 7,
            SyscallId::SolMemcmp => 8,
            SyscallId::Abort => 9,
            SyscallId::Unknown(h) => *h | 0x80000000,
        }
    }
    
    /// Create from u32 for deserialization
    pub fn from_u32(v: u32) -> Self {
        if v & 0x80000000 != 0 {
            return SyscallId::Unknown(v & 0x7FFFFFFF);
        }
        match v {
            1 => SyscallId::SolLog,
            2 => SyscallId::SolLog64,
            3 => SyscallId::SolLogPubkey,
            4 => SyscallId::SolLogComputeUnits,
            5 => SyscallId::SolMemcpy,
            6 => SyscallId::SolMemset,
            7 => SyscallId::SolMemmove,
            8 => SyscallId::SolMemcmp,
            9 => SyscallId::Abort,
            x => SyscallId::Unknown(x),
        }
    }
}

/// State of all BPF registers (r0-r10) and PC (r11)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterState {
    pub regs: [u64; 12],
}

impl RegisterState {
    pub fn new() -> Self {
        Self { regs: [0; 12] }
    }
    
    pub fn from_array(regs: [u64; 12]) -> Self {
        Self { regs }
    }
}

impl Default for RegisterState {
    fn default() -> Self {
        Self::new()
    }
}

/// A step in the execution trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Step {
    Instruction(InstructionTrace),
    Syscall(SyscallTrace),
}

impl Step {
    pub fn registers_before(&self) -> &RegisterState {
        match self {
            Step::Instruction(i) => &i.registers_before,
            Step::Syscall(s) => &s.registers_before,
        }
    }
    
    pub fn registers_after(&self) -> &RegisterState {
        match self {
            Step::Instruction(i) => &i.registers_after,
            Step::Syscall(s) => &s.registers_after,
        }
    }
    
    pub fn pc(&self) -> u64 {
        match self {
            Step::Instruction(i) => i.pc,
            Step::Syscall(s) => s.pc,
        }
    }
}

/// Trace of a single instruction execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionTrace {
    pub pc: u64,
    pub instruction_bytes: [u8; 8],
    pub registers_before: RegisterState,
    pub registers_after: RegisterState,
}

impl InstructionTrace {
    pub fn opcode(&self) -> u8 {
        self.instruction_bytes[0]
    }
    
    pub fn dst(&self) -> usize {
        (self.instruction_bytes[1] & 0x0f) as usize
    }
    
    pub fn src(&self) -> usize {
        ((self.instruction_bytes[1] >> 4) & 0x0f) as usize
    }
    
    pub fn offset(&self) -> i16 {
        i16::from_le_bytes([self.instruction_bytes[2], self.instruction_bytes[3]])
    }
    
    pub fn imm(&self) -> i32 {
        i32::from_le_bytes([
            self.instruction_bytes[4],
            self.instruction_bytes[5],
            self.instruction_bytes[6],
            self.instruction_bytes[7],
        ])
    }
}

/// Trace of a syscall invocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallTrace {
    pub pc: u64,
    pub syscall_id: SyscallId,
    pub raw_hash: u32,
    pub return_value: u64,
    pub registers_before: RegisterState,
    pub registers_after: RegisterState,
}

/// Complete execution trace of a BPF program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub steps: Vec<Step>,
    pub initial_registers: RegisterState,
    pub final_registers: RegisterState,
}

impl ExecutionTrace {
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            initial_registers: RegisterState::new(),
            final_registers: RegisterState::new(),
        }
    }
    
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
    
    pub fn instruction_count(&self) -> usize {
        self.steps.iter().filter(|s| matches!(s, Step::Instruction(_))).count()
    }
    
    pub fn syscall_count(&self) -> usize {
        self.steps.iter().filter(|s| matches!(s, Step::Syscall(_))).count()
    }
    
    /// Get all unique syscalls in this trace
    pub fn unique_syscalls(&self) -> Vec<SyscallId> {
        let mut seen = Vec::new();
        for step in &self.steps {
            if let Step::Syscall(s) = step {
                if !seen.contains(&s.syscall_id) {
                    seen.push(s.syscall_id);
                }
            }
        }
        seen
    }
    
    /// Check if all syscalls are whitelisted (no Unknown)
    pub fn all_syscalls_whitelisted(&self) -> bool {
        self.steps.iter().all(|s| match s {
            Step::Syscall(sc) => !sc.syscall_id.is_unknown(),
            _ => true,
        })
    }
    
    /// Count unknown syscalls
    pub fn unknown_syscall_count(&self) -> usize {
        self.steps.iter().filter(|s| match s {
            Step::Syscall(sc) => sc.syscall_id.is_unknown(),
            _ => false,
        }).count()
    }
    
    /// Validate trace with default strict policy
    pub fn validate(&self) -> Result<(), TraceValidationError> {
        self.validate_with_policy(&SyscallPolicy::strict())
    }
    
    /// Validate trace with custom policy
    pub fn validate_with_policy(&self, policy: &SyscallPolicy) -> Result<(), TraceValidationError> {
        for (idx, step) in self.steps.iter().enumerate() {
            match step {
                Step::Instruction(instr) => {
                    let opcode = instr.opcode();
                    if !opcodes::is_supported_insn(opcode) && !opcodes::is_syscall(opcode) {
                        return Err(TraceValidationError::UnsupportedOpcode { 
                            index: idx, 
                            pc: instr.pc, 
                            opcode,
                            name: opcodes::name(opcode),
                        });
                    }
                }
                Step::Syscall(syscall) => {
                    // Check if syscall is allowed under policy
                    if !policy.is_allowed(&syscall.syscall_id) {
                        return Err(TraceValidationError::UnsupportedSyscall {
                            index: idx,
                            pc: syscall.pc,
                            syscall_id: syscall.syscall_id,
                            raw_hash: syscall.raw_hash,
                        });
                    }
                    
                    // Get expected effects
                    if let Some(effects) = policy.effects(&syscall.syscall_id) {
                        // Check return value (if specific value expected)
                        if let Some(expected) = effects.expected_return {
                            if syscall.return_value != expected {
                                return Err(TraceValidationError::SyscallReturnMismatch {
                                    index: idx,
                                    pc: syscall.pc,
                                    syscall_id: syscall.syscall_id,
                                    expected,
                                    actual: syscall.return_value,
                                });
                            }
                        }
                        
                        // Check register preservation (r1-r5 should be unchanged for log syscalls)
                        if !effects.args_may_change {
                            for i in 1..=5 {
                                if syscall.registers_before.regs[i] != syscall.registers_after.regs[i] {
                                    return Err(TraceValidationError::SyscallRegisterChanged {
                                        index: idx,
                                        pc: syscall.pc,
                                        syscall_id: syscall.syscall_id,
                                        register: i,
                                    });
                                }
                            }
                        }
                        
                        // r6-r9 (callee-saved) should always be preserved
                        // Note: r10 (frame pointer) may change during syscall for stack management
                        for i in 6..=9 {
                            if syscall.registers_before.regs[i] != syscall.registers_after.regs[i] {
                                return Err(TraceValidationError::SyscallRegisterChanged {
                                    index: idx,
                                    pc: syscall.pc,
                                    syscall_id: syscall.syscall_id,
                                    register: i,
                                });
                            }
                        }
                        
                        // Note: Memory effects are NOT verified
                        // We allow memory syscalls but only check return value and register preservation
                        // This is a known limitation - memory correctness is NOT proven
                    }
                }
            }
        }
        Ok(())
    }
    
    pub fn pad_to_size(&mut self, target_size: usize) {
        if self.steps.len() >= target_size {
            self.steps.truncate(target_size);
            return;
        }
        
        let last_regs = if self.steps.is_empty() {
            self.initial_registers
        } else {
            *self.steps.last().unwrap().registers_after()
        };
        
        while self.steps.len() < target_size {
            self.steps.push(Step::Instruction(InstructionTrace {
                pc: 0,
                instruction_bytes: [0x00; 8],
                registers_before: last_regs,
                registers_after: last_regs,
            }));
        }
    }
    
    pub fn instructions(&self) -> Vec<&InstructionTrace> {
        self.steps.iter().filter_map(|s| match s {
            Step::Instruction(i) => Some(i),
            _ => None,
        }).collect()
    }
}

impl Default for ExecutionTrace {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors during trace validation
#[derive(Debug, Clone)]
pub enum TraceValidationError {
    UnsupportedOpcode { 
        index: usize, 
        pc: u64, 
        opcode: u8, 
        name: &'static str 
    },
    UnsupportedSyscall { 
        index: usize, 
        pc: u64, 
        syscall_id: SyscallId, 
        raw_hash: u32 
    },
    SyscallReturnMismatch {
        index: usize,
        pc: u64,
        syscall_id: SyscallId,
        expected: u64,
        actual: u64,
    },
    SyscallRegisterChanged {
        index: usize,
        pc: u64,
        syscall_id: SyscallId,
        register: usize,
    },
    MemoryEffectsNotSupported {
        index: usize,
        pc: u64,
        syscall_id: SyscallId,
    },
}

impl core::fmt::Display for TraceValidationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedOpcode { index, pc, opcode, name } => {
                write!(f, "Unsupported opcode 0x{:02x} ({}) at step {} (pc={})", opcode, name, index, pc)
            }
            Self::UnsupportedSyscall { index, pc, syscall_id, raw_hash } => {
                write!(f, "Unsupported syscall {:?} (hash=0x{:08x}) at step {} (pc={})", syscall_id, raw_hash, index, pc)
            }
            Self::SyscallReturnMismatch { index, pc, syscall_id, expected, actual } => {
                write!(f, "Syscall {:?} at step {} (pc={}) returned {} but expected {}", 
                       syscall_id, index, pc, actual, expected)
            }
            Self::SyscallRegisterChanged { index, pc, syscall_id, register } => {
                write!(f, "Syscall {:?} at step {} (pc={}) modified r{} which should be preserved",
                       syscall_id, index, pc, register)
            }
            Self::MemoryEffectsNotSupported { index, pc, syscall_id } => {
                write!(f, "Syscall {:?} at step {} (pc={}) has memory effects which are not supported",
                       syscall_id, index, pc)
            }
        }
    }
}

/// Validation result with detailed info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub error: Option<String>,
    pub syscall_summary: SyscallSummary,
}

/// Summary of syscalls in trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallSummary {
    pub total: usize,
    pub whitelisted: usize,
    pub unknown: usize,
    pub unique_hashes: Vec<u32>,
}

impl ExecutionTrace {
    /// Get detailed validation result
    pub fn validation_result(&self, policy: &SyscallPolicy) -> ValidationResult {
        let syscalls: Vec<_> = self.steps.iter().filter_map(|s| match s {
            Step::Syscall(sc) => Some(sc),
            _ => None,
        }).collect();
        
        let whitelisted = syscalls.iter().filter(|s| !s.syscall_id.is_unknown()).count();
        let unknown = syscalls.len() - whitelisted;
        
        let mut unique_hashes: Vec<u32> = syscalls.iter().map(|s| s.raw_hash).collect();
        unique_hashes.sort();
        unique_hashes.dedup();
        
        let summary = SyscallSummary {
            total: syscalls.len(),
            whitelisted,
            unknown,
            unique_hashes,
        };
        
        match self.validate_with_policy(policy) {
            Ok(()) => ValidationResult {
                valid: true,
                error: None,
                syscall_summary: summary,
            },
            Err(e) => ValidationResult {
                valid: false,
                error: Some(format!("{}", e)),
                syscall_summary: summary,
            },
        }
    }
}

/// Binary serialization for trace files (v2 with syscall support)
pub mod binary {
    use super::*;
    
    const STEP_TYPE_INSTRUCTION: u8 = 0;
    const STEP_TYPE_SYSCALL: u8 = 1;
    
    pub fn serialize(trace: &ExecutionTrace) -> Vec<u8> {
        let mut buf = Vec::new();
        
        buf.extend_from_slice(TRACE_MAGIC);
        buf.extend_from_slice(&TRACE_VERSION.to_le_bytes());
        
        for reg in &trace.initial_registers.regs {
            buf.extend_from_slice(&reg.to_le_bytes());
        }
        
        for reg in &trace.final_registers.regs {
            buf.extend_from_slice(&reg.to_le_bytes());
        }
        
        let count = trace.steps.len() as u32;
        buf.extend_from_slice(&count.to_le_bytes());
        
        for step in &trace.steps {
            match step {
                Step::Instruction(instr) => {
                    buf.push(STEP_TYPE_INSTRUCTION);
                    buf.extend_from_slice(&instr.pc.to_le_bytes());
                    buf.extend_from_slice(&instr.instruction_bytes);
                    for reg in &instr.registers_before.regs {
                        buf.extend_from_slice(&reg.to_le_bytes());
                    }
                    for reg in &instr.registers_after.regs {
                        buf.extend_from_slice(&reg.to_le_bytes());
                    }
                }
                Step::Syscall(syscall) => {
                    buf.push(STEP_TYPE_SYSCALL);
                    buf.extend_from_slice(&syscall.pc.to_le_bytes());
                    buf.extend_from_slice(&syscall.syscall_id.to_u32().to_le_bytes());
                    buf.extend_from_slice(&syscall.raw_hash.to_le_bytes());
                    buf.extend_from_slice(&syscall.return_value.to_le_bytes());
                    for reg in &syscall.registers_before.regs {
                        buf.extend_from_slice(&reg.to_le_bytes());
                    }
                    for reg in &syscall.registers_after.regs {
                        buf.extend_from_slice(&reg.to_le_bytes());
                    }
                }
            }
        }
        
        buf
    }
    
    pub fn deserialize(data: &[u8]) -> Result<ExecutionTrace, DeserializeError> {
        let mut pos = 0;
        
        if data.len() < 8 + 4 + 96 + 96 + 4 {
            return Err(DeserializeError::TooShort);
        }
        
        if &data[pos..pos + 8] != TRACE_MAGIC {
            if &data[pos..pos + 8] == b"SBPFZK01" {
                return deserialize_v1(data);
            }
            return Err(DeserializeError::InvalidMagic);
        }
        pos += 8;
        
        let version = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        if version != TRACE_VERSION {
            return Err(DeserializeError::UnsupportedVersion(version));
        }
        pos += 4;
        
        let mut initial_regs = [0u64; 12];
        for reg in &mut initial_regs {
            *reg = u64::from_le_bytes([
                data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
            ]);
            pos += 8;
        }
        
        let mut final_regs = [0u64; 12];
        for reg in &mut final_regs {
            *reg = u64::from_le_bytes([
                data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
            ]);
            pos += 8;
        }
        
        let count = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        
        let mut steps = Vec::with_capacity(count);
        for _ in 0..count {
            if pos >= data.len() {
                return Err(DeserializeError::TooShort);
            }
            
            let step_type = data[pos];
            pos += 1;
            
            match step_type {
                STEP_TYPE_INSTRUCTION => {
                    let pc = u64::from_le_bytes([
                        data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                        data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                    ]);
                    pos += 8;
                    
                    let mut instruction_bytes = [0u8; 8];
                    instruction_bytes.copy_from_slice(&data[pos..pos + 8]);
                    pos += 8;
                    
                    let mut regs_before = [0u64; 12];
                    for reg in &mut regs_before {
                        *reg = u64::from_le_bytes([
                            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                        ]);
                        pos += 8;
                    }
                    
                    let mut regs_after = [0u64; 12];
                    for reg in &mut regs_after {
                        *reg = u64::from_le_bytes([
                            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                        ]);
                        pos += 8;
                    }
                    
                    steps.push(Step::Instruction(InstructionTrace {
                        pc,
                        instruction_bytes,
                        registers_before: RegisterState { regs: regs_before },
                        registers_after: RegisterState { regs: regs_after },
                    }));
                }
                STEP_TYPE_SYSCALL => {
                    let pc = u64::from_le_bytes([
                        data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                        data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                    ]);
                    pos += 8;
                    
                    let syscall_id_raw = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                    pos += 4;
                    let syscall_id = SyscallId::from_u32(syscall_id_raw);
                    
                    let raw_hash = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                    pos += 4;
                    
                    let return_value = u64::from_le_bytes([
                        data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                        data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                    ]);
                    pos += 8;
                    
                    let mut regs_before = [0u64; 12];
                    for reg in &mut regs_before {
                        *reg = u64::from_le_bytes([
                            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                        ]);
                        pos += 8;
                    }
                    
                    let mut regs_after = [0u64; 12];
                    for reg in &mut regs_after {
                        *reg = u64::from_le_bytes([
                            data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                            data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                        ]);
                        pos += 8;
                    }
                    
                    steps.push(Step::Syscall(SyscallTrace {
                        pc,
                        syscall_id,
                        raw_hash,
                        return_value,
                        registers_before: RegisterState { regs: regs_before },
                        registers_after: RegisterState { regs: regs_after },
                    }));
                }
                _ => {
                    return Err(DeserializeError::InvalidStepType(step_type));
                }
            }
        }
        
        Ok(ExecutionTrace {
            steps,
            initial_registers: RegisterState { regs: initial_regs },
            final_registers: RegisterState { regs: final_regs },
        })
    }
    
    fn deserialize_v1(data: &[u8]) -> Result<ExecutionTrace, DeserializeError> {
        let mut pos = 8;
        
        let _version = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
        
        let mut initial_regs = [0u64; 12];
        for reg in &mut initial_regs {
            *reg = u64::from_le_bytes([
                data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
            ]);
            pos += 8;
        }
        
        let mut final_regs = [0u64; 12];
        for reg in &mut final_regs {
            *reg = u64::from_le_bytes([
                data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
            ]);
            pos += 8;
        }
        
        let count = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        
        let mut steps = Vec::with_capacity(count);
        for _ in 0..count {
            let pc = u64::from_le_bytes([
                data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
            ]);
            pos += 8;
            
            let mut instruction_bytes = [0u8; 8];
            instruction_bytes.copy_from_slice(&data[pos..pos + 8]);
            pos += 8;
            
            let mut regs_before = [0u64; 12];
            for reg in &mut regs_before {
                *reg = u64::from_le_bytes([
                    data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                    data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                ]);
                pos += 8;
            }
            
            let mut regs_after = [0u64; 12];
            for reg in &mut regs_after {
                *reg = u64::from_le_bytes([
                    data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                    data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7],
                ]);
                pos += 8;
            }
            
            if instruction_bytes[0] == opcodes::CALL_IMM {
                let imm = i32::from_le_bytes([
                    instruction_bytes[4], instruction_bytes[5],
                    instruction_bytes[6], instruction_bytes[7],
                ]);
                let raw_hash = imm as u32;
                
                if let Some(syscall_id) = SyscallId::from_imm(imm) {
                    // Known syscall
                    steps.push(Step::Syscall(SyscallTrace {
                        pc,
                        syscall_id,
                        raw_hash,
                        return_value: regs_after[0],
                        registers_before: RegisterState { regs: regs_before },
                        registers_after: RegisterState { regs: regs_after },
                    }));
                } else {
                    // Internal function call - treat as instruction
                    steps.push(Step::Instruction(InstructionTrace {
                        pc,
                        instruction_bytes,
                        registers_before: RegisterState { regs: regs_before },
                        registers_after: RegisterState { regs: regs_after },
                    }));
                }
            } else {
                steps.push(Step::Instruction(InstructionTrace {
                    pc,
                    instruction_bytes,
                    registers_before: RegisterState { regs: regs_before },
                    registers_after: RegisterState { regs: regs_after },
                }));
            }
        }
        
        Ok(ExecutionTrace {
            steps,
            initial_registers: RegisterState { regs: initial_regs },
            final_registers: RegisterState { regs: final_regs },
        })
    }
    
    #[derive(Debug, Clone)]
    pub enum DeserializeError {
        TooShort,
        InvalidMagic,
        UnsupportedVersion(u32),
        InvalidStepType(u8),
    }
    
    impl core::fmt::Display for DeserializeError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::TooShort => write!(f, "Trace data too short"),
                Self::InvalidMagic => write!(f, "Invalid trace file magic bytes"),
                Self::UnsupportedVersion(v) => write!(f, "Unsupported trace version: {}", v),
                Self::InvalidStepType(t) => write!(f, "Invalid step type: {}", t),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_strict_policy_rejects_unknown() {
        let policy = SyscallPolicy::strict();
        assert!(!policy.is_allowed(&SyscallId::Unknown(0x12345678)));
        assert!(policy.is_allowed(&SyscallId::SolLog));
    }
    
    #[test]
    fn test_debug_policy_allows_unknown() {
        let policy = SyscallPolicy::debug();
        assert!(policy.is_allowed(&SyscallId::Unknown(0x12345678)));
    }
    
    #[test]
    fn test_validate_rejects_unknown_syscall() {
        let mut trace = ExecutionTrace::new();
        trace.steps.push(Step::Syscall(SyscallTrace {
            pc: 0,
            syscall_id: SyscallId::Unknown(0x12345678),
            raw_hash: 0x12345678,
            return_value: 0,
            registers_before: RegisterState::new(),
            registers_after: RegisterState::new(),
        }));
        
        // Strict policy should reject
        assert!(trace.validate().is_err());
        
        // Debug policy should allow
        assert!(trace.validate_with_policy(&SyscallPolicy::debug()).is_ok());
    }
    
    #[test]
    fn test_roundtrip_instruction() {
        let mut trace = ExecutionTrace::new();
        trace.initial_registers.regs[0] = 42;
        trace.final_registers.regs[0] = 43;
        
        trace.steps.push(Step::Instruction(InstructionTrace {
            pc: 0,
            instruction_bytes: [0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            registers_before: RegisterState { regs: [42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
            registers_after: RegisterState { regs: [43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] },
        }));
        
        let serialized = binary::serialize(&trace);
        let deserialized = binary::deserialize(&serialized).unwrap();
        
        assert_eq!(trace.steps.len(), deserialized.steps.len());
    }
    
    #[test]
    fn test_roundtrip_syscall() {
        let mut trace = ExecutionTrace::new();
        
        trace.steps.push(Step::Syscall(SyscallTrace {
            pc: 100,
            syscall_id: SyscallId::SolLog,
            raw_hash: 0x56ffab99,
            return_value: 0,
            registers_before: RegisterState::new(),
            registers_after: RegisterState::new(),
        }));
        
        let serialized = binary::serialize(&trace);
        let deserialized = binary::deserialize(&serialized).unwrap();
        
        assert_eq!(trace.steps.len(), deserialized.steps.len());
        match &deserialized.steps[0] {
            Step::Syscall(s) => {
                assert_eq!(s.syscall_id, SyscallId::SolLog);
            }
            _ => panic!("Expected syscall"),
        }
    }
}
