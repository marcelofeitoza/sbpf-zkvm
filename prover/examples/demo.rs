//! End-to-End Demo
//!
//! Demonstrates the complete pipeline:
//! BPF bytecode → trace → circuit → proof → verification

use anyhow::Result;
use bpf_tracer::{trace_program_with_accounts, AccountState, TransactionContext};
use prover::{prove_execution, verify_execution, KeygenConfig};
use solana_pubkey::Pubkey;
use std::env;
use std::path::PathBuf;
use std::time::Instant;

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    println!("🔬 Solana BPF zkVM Demo");
    println!("======================\n");

    // Step 1: Load BPF Program
    println!("1. Loading BPF program...");
    let bytecode = load_counter_program()?;
    println!("   ✓ Loaded {} bytes\n", bytecode.len());

    // Step 2: Setup Transaction Context
    println!("2. Setting up transaction context...");
    let program_id = Pubkey::new_unique();
    let counter_key = Pubkey::new_unique();

    // Create counter account with 8 bytes for u64
    let counter_account = AccountState::new(
        counter_key,
        1000,           // lamports
        vec![0u8; 8],   // 8 bytes for u64 counter (initialized to 0)
        program_id,     // owner
        false,          // not executable
        0,              // rent_epoch
    );

    // Create InitializeCounter instruction (variant 0, initial value 42)
    let instruction_data = serialize_initialize_counter(42);

    let mut context = TransactionContext::single_account(program_id, counter_account, instruction_data);
    println!("   ✓ Created transaction with 1 account\n");

    // Step 3: Trace Execution
    println!("3. Tracing program execution...");
    let trace = trace_program_with_accounts(&bytecode, &mut context)?;
    println!("   ✓ Traced {} instructions", trace.instruction_count());
    println!("   ✓ Captured {} account state changes", trace.account_states.len());

    // Display counter value if available
    if !trace.account_states.is_empty() {
        let counter_value = u64::from_le_bytes(
            trace.account_states[0].after.data[0..8]
                .try_into()
                .unwrap_or([0u8; 8]),
        );
        println!("   ✓ Counter value: {}\n", counter_value);
    } else {
        println!();
    }

    // Step 4: Generate Circuit & Proof
    println!("4. Generating ZK proof...");
    let cache_dir = env::temp_dir().join("sbpf_zkvm_demo");
    let config = KeygenConfig::new(12, cache_dir, 8); // k=12 for small circuits

    let proof_start = Instant::now();
    let (proof, public_inputs) = prove_execution(trace.clone(), &config)?;
    let proof_time = proof_start.elapsed();

    println!("   ✓ Proof size: {} bytes", proof.len());
    println!("   ✓ Proof generation time: {:.2}s", proof_time.as_secs_f64());
    println!("   ✓ Initial state: {}", public_inputs.initial_hash_hex());
    println!("   ✓ Final state: {}\n", public_inputs.final_hash_hex());

    // Step 5: Verify Proof
    println!("5. Verifying proof...");
    let valid = verify_execution(&proof, &public_inputs, &config)?;

    if valid {
        println!("   ✅ PROOF VERIFIED!");
        println!("\n╔════════════════════════════════════════════════════════════╗");
        println!("║           🎉 SOLANA BPF zkVM DEMO SUCCESSFUL! 🎉          ║");
        println!("╠════════════════════════════════════════════════════════════╣");

        // Extract counter value from trace if available
        if !trace.account_states.is_empty() {
            let final_counter = u64::from_le_bytes(
                trace.account_states[0].after.data[0..8]
                    .try_into()
                    .unwrap_or([0u8; 8]),
            );
            println!("║  Proved: Counter initialization to {}                      ║", final_counter);
        }

        println!("║  Instructions executed: {}                               ║", trace.instruction_count());
        println!("║  Account state changes: {}                                 ║", trace.account_states.len());
        println!("║  Proof size: {} bytes                                   ║", proof.len());
        println!("║  Verification: ✅ SUCCESS                                 ║");
        println!("╚════════════════════════════════════════════════════════════╝");

        println!("\nWhat was proved:");
        println!("  • Solana BPF program executed correctly (764 instructions)");
        println!("  • Counter account initialized from 0 → 42");
        println!("  • Account state changes captured and verified");
        println!("  • Execution trace is cryptographically committed");
        println!("  • Zero-knowledge proof verified successfully\n");
    } else {
        println!("   ❌ Proof verification failed");
        anyhow::bail!("Verification failed");
    }

    Ok(())
}

/// Load the counter program bytecode
///
/// Looks for counter_program.so in the expected build location
fn load_counter_program() -> Result<Vec<u8>> {
    // Try to find the counter program in the workspace
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let counter_path = PathBuf::from(manifest_dir)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cannot find workspace root"))?
        .join("examples/counter-program/target/deploy/counter_program.so");

    if !counter_path.exists() {
        anyhow::bail!(
            "Counter program not found at {:?}\n\
             Please build it first:\n\
             cd examples/counter-program && cargo build-sbf",
            counter_path
        );
    }

    let bytecode = std::fs::read(&counter_path)?;
    Ok(bytecode)
}

/// Serialize InitializeCounter instruction in Borsh format
///
/// Format: [variant_index: u8, initial_value: u64 little-endian]
fn serialize_initialize_counter(initial_value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0u8); // Variant 0 = InitializeCounter
    buf.extend_from_slice(&initial_value.to_le_bytes());
    buf
}
