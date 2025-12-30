//! Trace Exporter CLI
//!
//! Exports execution traces from the real Solana BPF VM for use in the browser zkVM.

use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use trace_core::{
    binary, ExecutionTrace, InstructionTrace, RegisterState, Step, 
    SyscallId, SyscallTrace, SyscallPolicy, opcodes,
};
use bpf_tracer::trace::AccountState;
use bpf_tracer::transaction::TransactionContext;

/// Export execution traces from Solana BPF programs
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Output file for the trace
    #[arg(short, long, default_value = "counter.trace")]
    out: PathBuf,
    
    /// Initial counter value
    #[arg(short, long, default_value = "0")]
    initial: u64,
    
    /// Path to BPF program ELF (uses built-in counter-program if not specified)
    #[arg(short, long)]
    program: Option<PathBuf>,
    
    /// Allow unknown syscalls (debug mode only - NOT for production proofs)
    #[arg(long, default_value = "false")]
    allow_unknown_syscalls: bool,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("trace_exporter=info".parse().unwrap())
                .add_directive("bpf_tracer=info".parse().unwrap()),
        )
        .init();
    
    let args = Args::parse();
    
    tracing::info!("Trace Exporter - Solana BPF zkVM");
    tracing::info!("================================");
    
    if args.allow_unknown_syscalls {
        tracing::warn!("⚠️  DEBUG MODE: Unknown syscalls allowed");
        tracing::warn!("⚠️  Traces exported in this mode may not be provable in production");
    }
    
    // Load BPF program
    let bytecode = if let Some(program_path) = &args.program {
        tracing::info!("Loading BPF program from: {}", program_path.display());
        fs::read(program_path)
            .with_context(|| format!("Failed to read program: {}", program_path.display()))?
    } else {
        let default_path = PathBuf::from("examples/counter-program/target/sbf-solana-solana/release/counter_program.so");
        if default_path.exists() {
            tracing::info!("Loading built-in counter program from: {}", default_path.display());
            fs::read(&default_path)
                .with_context(|| format!("Failed to read program: {}", default_path.display()))?
        } else {
            anyhow::bail!(
                "Counter program not found at {}. Build it first with:\n  cargo build-sbf --manifest-path examples/counter-program/Cargo.toml",
                default_path.display()
            );
        }
    };
    
    tracing::info!("Loaded {} bytes of BPF bytecode", bytecode.len());
    
    // Create transaction context with counter account
    let mut ctx = create_counter_context(args.initial);
    
    tracing::info!("Initial counter value: {}", args.initial);
    
    // Run the real Solana VM and capture trace
    tracing::info!("Executing BPF program...");
    let bpf_trace = bpf_tracer::vm::trace_program_with_accounts(&bytecode, &mut ctx)
        .context("Failed to execute BPF program")?;
    
    tracing::info!("Executed {} instructions", bpf_trace.instruction_count());
    
    // Convert bpf-tracer trace to trace-core format (with syscall support)
    let trace = convert_trace(&bpf_trace);
    
    let insn_count = trace.instruction_count();
    let syscall_count = trace.syscall_count();
    let unknown_count = trace.unknown_syscall_count();
    
    tracing::info!("Converted trace: {} instructions, {} syscalls ({} unknown)", 
                   insn_count, syscall_count, unknown_count);
    
    // Validate trace with appropriate policy
    let policy = if args.allow_unknown_syscalls {
        SyscallPolicy::debug()
    } else {
        SyscallPolicy::strict()
    };
    
    let validation = trace.validation_result(&policy);
    
    if validation.valid {
        tracing::info!("Trace validation: OK");
    } else {
        if args.allow_unknown_syscalls {
            tracing::warn!("Trace validation warning: {}", validation.error.as_deref().unwrap_or("unknown"));
            tracing::warn!("Continuing because --allow-unknown-syscalls is set");
        } else {
            tracing::error!("Trace validation FAILED: {}", validation.error.as_deref().unwrap_or("unknown"));
            tracing::error!("");
            tracing::error!("The trace contains syscalls that are not whitelisted.");
            tracing::error!("Unique syscall hashes found:");
            for hash in &validation.syscall_summary.unique_hashes {
                tracing::error!("  0x{:08x}", hash);
            }
            tracing::error!("");
            tracing::error!("Options:");
            tracing::error!("  1. Use --allow-unknown-syscalls for debugging (NOT production)");
            tracing::error!("  2. Add these syscalls to the whitelist in trace-core");
            anyhow::bail!("Trace validation failed");
        }
    }
    
    // Serialize to binary (v2 format with syscall support)
    let trace_bytes = binary::serialize(&trace);
    
    // Write to file
    fs::write(&args.out, &trace_bytes)
        .with_context(|| format!("Failed to write trace to: {}", args.out.display()))?;
    
    // Print summary
    println!();
    println!("✓ Trace exported successfully!");
    println!("  Output: {}", args.out.display());
    println!("  Size: {} bytes", trace_bytes.len());
    println!("  Steps: {} ({} instructions, {} syscalls)", 
             trace.step_count(), insn_count, syscall_count);
    println!("  Syscall summary:");
    println!("    Whitelisted: {}", validation.syscall_summary.whitelisted);
    println!("    Unknown: {}", validation.syscall_summary.unknown);
    println!("  Initial r0: {}", trace.initial_registers.regs[0]);
    println!("  Final r0: {}", trace.final_registers.regs[0]);
    
    if !bpf_trace.account_states.is_empty() {
        let change = &bpf_trace.account_states[0];
        if change.after.data.len() >= 8 {
            let counter_value = u64::from_le_bytes(
                change.after.data[0..8].try_into().unwrap()
            );
            println!("  Counter value: {} → {}", args.initial, counter_value);
        }
    }
    
    if validation.syscall_summary.unknown > 0 && !args.allow_unknown_syscalls {
        println!();
        println!("⚠️  Warning: {} unknown syscalls in trace", validation.syscall_summary.unknown);
        println!("   These will be rejected by the zkVM prover unless --allow-unknown-syscalls is used");
    }
    
    Ok(())
}

/// Create a transaction context for the counter program
fn create_counter_context(initial_value: u64) -> TransactionContext {
    use solana_pubkey::Pubkey;
    
    let counter_pubkey = Pubkey::new_unique();
    let program_id = Pubkey::new_unique();
    
    // Create counter account data (8 bytes for u64 counter + 8 byte discriminator)
    let mut data = vec![0u8; 16];
    data[0..8].copy_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]); // discriminator
    data[8..16].copy_from_slice(&initial_value.to_le_bytes());
    
    let account = AccountState::new(
        counter_pubkey,
        1_000_000,
        data,
        program_id,
        false,
        0,
    );
    
    let instruction_data = vec![1]; // increment instruction
    
    TransactionContext::single_account(program_id, account, instruction_data)
}

/// Convert bpf-tracer ExecutionTrace to trace-core ExecutionTrace
fn convert_trace(bpf_trace: &bpf_tracer::trace::ExecutionTrace) -> ExecutionTrace {
    let mut trace = ExecutionTrace::new();
    
    trace.initial_registers = RegisterState::from_array(bpf_trace.initial_registers.regs);
    trace.final_registers = RegisterState::from_array(bpf_trace.final_registers.regs);
    
    for instr in &bpf_trace.instructions {
        let mut instruction_bytes = [0u8; 8];
        let len = instr.instruction_bytes.len().min(8);
        instruction_bytes[..len].copy_from_slice(&instr.instruction_bytes[..len]);
        
        let opcode = instruction_bytes[0];
        
        if opcodes::is_syscall(opcode) {
            let imm = i32::from_le_bytes([
                instruction_bytes[4], instruction_bytes[5],
                instruction_bytes[6], instruction_bytes[7],
            ]);
            let raw_hash = imm as u32;
            
            // Check if this is a known syscall or an internal function call
            if let Some(syscall_id) = SyscallId::from_imm(imm) {
                // Known syscall
                let return_value = instr.registers_after.regs[0];
                
                trace.steps.push(Step::Syscall(SyscallTrace {
                    pc: instr.pc,
                    syscall_id,
                    raw_hash,
                    return_value,
                    registers_before: RegisterState::from_array(instr.registers_before.regs),
                    registers_after: RegisterState::from_array(instr.registers_after.regs),
                }));
            } else {
                // Not a known syscall - internal BPF function call
                // Treat as regular instruction
                trace.steps.push(Step::Instruction(InstructionTrace {
                    pc: instr.pc,
                    instruction_bytes,
                    registers_before: RegisterState::from_array(instr.registers_before.regs),
                    registers_after: RegisterState::from_array(instr.registers_after.regs),
                }));
            }
        } else {
            trace.steps.push(Step::Instruction(InstructionTrace {
                pc: instr.pc,
                instruction_bytes,
                registers_before: RegisterState::from_array(instr.registers_before.regs),
                registers_after: RegisterState::from_array(instr.registers_after.regs),
            }));
        }
    }
    
    trace
}
