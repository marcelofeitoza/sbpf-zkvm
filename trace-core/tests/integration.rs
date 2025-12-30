//! Integration tests for trace serialization with syscalls

use trace_core::{
    binary, ExecutionTrace, InstructionTrace, RegisterState, Step, SyscallId, SyscallTrace,
};

/// Test that a trace with instructions and syscalls roundtrips correctly
#[test]
fn test_roundtrip_mixed_trace() {
    let mut trace = ExecutionTrace::new();
    trace.initial_registers.regs[0] = 0;
    trace.initial_registers.regs[2] = 42;

    // Instruction: ADD64_IMM r2, 1
    trace.steps.push(Step::Instruction(InstructionTrace {
        pc: 100,
        instruction_bytes: [0x07, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
        registers_before: RegisterState {
            regs: [0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 100],
        },
        registers_after: RegisterState {
            regs: [0, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 101],
        },
    }));

    // Syscall: sol_log_
    trace.steps.push(Step::Syscall(SyscallTrace {
        pc: 101,
        syscall_id: SyscallId::SolLog,
        raw_hash: 0x56ffab99,
        return_value: 0,
        registers_before: RegisterState {
            regs: [0, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 101],
        },
        registers_after: RegisterState {
            regs: [0, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 200],
        },
    }));

    // Another instruction: MOV64_REG r0, r2
    trace.steps.push(Step::Instruction(InstructionTrace {
        pc: 200,
        instruction_bytes: [0xbf, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        registers_before: RegisterState {
            regs: [0, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 200],
        },
        registers_after: RegisterState {
            regs: [43, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 201],
        },
    }));

    // Exit
    trace.steps.push(Step::Instruction(InstructionTrace {
        pc: 201,
        instruction_bytes: [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        registers_before: RegisterState {
            regs: [43, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 201],
        },
        registers_after: RegisterState {
            regs: [43, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 202],
        },
    }));

    trace.final_registers = RegisterState {
        regs: [43, 0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 202],
    };

    // Serialize
    let bytes = binary::serialize(&trace);
    assert!(bytes.len() > 0);

    // Deserialize
    let loaded = binary::deserialize(&bytes).expect("deserialization should succeed");

    // Verify
    assert_eq!(loaded.step_count(), 4);
    assert_eq!(loaded.instruction_count(), 3);
    assert_eq!(loaded.syscall_count(), 1);
    assert_eq!(loaded.initial_registers.regs[2], 42);
    assert_eq!(loaded.final_registers.regs[0], 43);

    // Validate
    assert!(loaded.validate().is_ok());
}

/// Test validation rejects unknown opcodes
#[test]
fn test_validation_rejects_unsupported() {
    let mut trace = ExecutionTrace::new();

    // Unknown opcode 0xFF
    trace.steps.push(Step::Instruction(InstructionTrace {
        pc: 0,
        instruction_bytes: [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        registers_before: RegisterState::new(),
        registers_after: RegisterState::new(),
    }));

    let result = trace.validate();
    assert!(result.is_err());
}

/// Test padding preserves register state
#[test]
fn test_pad_to_size() {
    let mut trace = ExecutionTrace::new();
    trace.initial_registers.regs[0] = 42;

    trace.steps.push(Step::Instruction(InstructionTrace {
        pc: 0,
        instruction_bytes: [0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
        registers_before: RegisterState {
            regs: [42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        },
        registers_after: RegisterState {
            regs: [43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        },
    }));

    trace.pad_to_size(100);

    assert_eq!(trace.steps.len(), 100);

    // First step should be unchanged
    match &trace.steps[0] {
        Step::Instruction(i) => assert_eq!(i.registers_after.regs[0], 43),
        _ => panic!("Expected instruction"),
    }

    // Padding should preserve final state
    match &trace.steps[99] {
        Step::Instruction(i) => {
            assert_eq!(i.registers_before.regs[0], 43);
            assert_eq!(i.registers_after.regs[0], 43);
        }
        _ => panic!("Expected instruction"),
    }
}

/// Test syscall IDs serialize correctly
#[test]
fn test_syscall_id_roundtrip() {
    let ids = vec![
        SyscallId::SolLog,
        SyscallId::SolLog64,
        SyscallId::SolMemcpy,
        SyscallId::Unknown(0x12345678),
    ];

    for id in ids {
        let encoded = id.to_u32();
        let decoded = SyscallId::from_u32(encoded);
        assert_eq!(id, decoded);
    }
}

/// Test that v1 format (legacy) can still be read
#[test]
fn test_v1_backwards_compatibility() {
    // Create a minimal v1 format trace manually
    let mut buf = Vec::new();

    // Magic bytes (v1)
    buf.extend_from_slice(b"SBPFZK01");

    // Version
    buf.extend_from_slice(&1u32.to_le_bytes());

    // Initial registers (12 * 8 = 96 bytes)
    for i in 0..12u64 {
        buf.extend_from_slice(&i.to_le_bytes());
    }

    // Final registers (12 * 8 = 96 bytes)
    for i in 0..12u64 {
        buf.extend_from_slice(&(i + 100).to_le_bytes());
    }

    // Instruction count = 1
    buf.extend_from_slice(&1u32.to_le_bytes());

    // One instruction: pc, instruction_bytes, regs_before (12*8), regs_after (12*8)
    buf.extend_from_slice(&42u64.to_le_bytes()); // pc
    buf.extend_from_slice(&[0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]); // ADD64_IMM r0, 1
    for i in 0..12u64 {
        buf.extend_from_slice(&i.to_le_bytes()); // regs_before
    }
    for i in 0..12u64 {
        buf.extend_from_slice(&(i + 1).to_le_bytes()); // regs_after
    }

    // Deserialize
    let trace = binary::deserialize(&buf).expect("v1 format should be readable");

    assert_eq!(trace.step_count(), 1);
    assert_eq!(trace.instruction_count(), 1);
    match &trace.steps[0] {
        Step::Instruction(i) => {
            assert_eq!(i.pc, 42);
            assert_eq!(i.opcode(), 0x07);
        }
        _ => panic!("Expected instruction"),
    }
}


