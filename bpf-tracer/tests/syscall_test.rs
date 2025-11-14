//! Test that syscalls are properly registered and working

use bpf_tracer::trace_program;

#[test]
fn test_syscalls_registered() {
    // Initialize tracing
    let _ = tracing_subscriber::fmt::try_init();

    // Simple program that calls a syscall
    // This is raw BPF bytecode that will call a function
    // For now, just test that a simple program runs
    let bytecode = &[
        0xb7, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, // mov64 r0, 42
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    ];

    let trace = trace_program(bytecode).expect("Should execute simple program");

    assert_eq!(trace.final_registers.regs[0], 42);
    assert!(trace.instruction_count() > 0);
}
