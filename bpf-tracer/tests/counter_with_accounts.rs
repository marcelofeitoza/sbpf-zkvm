//! Integration test for counter program with Solana account handling

use bpf_tracer::{trace_program_with_accounts, AccountState, TransactionContext};
use solana_pubkey::Pubkey;
use std::path::PathBuf;

// Manually serialize counter instructions in borsh format
fn serialize_initialize_counter(initial_value: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0u8); // Variant index for InitializeCounter
    buf.extend_from_slice(&initial_value.to_le_bytes());
    buf
}

fn serialize_increment_counter() -> Vec<u8> {
    vec![1u8] // Variant index for IncrementCounter
}

#[test]
#[ignore] // Requires counter program to be built first
fn test_counter_program_with_accounts() {
    // Initialize tracing
    let _ = tracing_subscriber::fmt::try_init();

    // Load the counter program binary
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let counter_so_path = manifest_dir
        .parent()
        .unwrap()
        .join("examples/counter-program/target/deploy/counter_program.so");

    if !counter_so_path.exists() {
        panic!(
            "Counter program not found at {:?}. Run 'cargo build-sbf' in examples/counter-program first",
            counter_so_path
        );
    }

    let bytecode = std::fs::read(&counter_so_path).expect("Failed to read counter program");

    tracing::info!(
        "Loaded counter program: {} bytes from {:?}",
        bytecode.len(),
        counter_so_path
    );

    // Create program ID and counter account
    let program_id = Pubkey::new_unique();
    let counter_key = Pubkey::new_unique();

    // Create counter account with 8 bytes for u64
    let counter_account = AccountState::new(
        counter_key,
        1000, // lamports
        vec![0u8; 8], // 8 bytes for u64 counter (initialized to 0)
        program_id, // owner
        false,      // not executable
        0,          // rent_epoch
    );

    // Create InitializeCounter instruction (initialize to 42)
    let instruction_data = serialize_initialize_counter(42);

    // Create transaction context
    let mut context =
        TransactionContext::single_account(program_id, counter_account, instruction_data);

    // Execute the program and trace
    let trace =
        trace_program_with_accounts(&bytecode, &mut context).expect("Failed to trace program");

    tracing::info!("Program executed {} instructions", trace.instruction_count());
    tracing::info!("Account state changes: {}", trace.account_states.len());

    // Verify execution succeeded (r0 should be 0 for success)
    assert_eq!(
        trace.final_registers.regs[0], 0,
        "Program should return 0 for success"
    );

    // Verify account was modified
    assert_eq!(
        trace.account_states.len(),
        1,
        "Should have 1 account state change"
    );

    // Verify the counter was initialized to 42
    let account_change = &trace.account_states[0];
    assert!(
        account_change.data_changed(),
        "Account data should have changed"
    );

    // The account data should now contain 42 as a little-endian u64
    let counter_value = u64::from_le_bytes(
        account_change.after.data[0..8]
            .try_into()
            .expect("Account data should be at least 8 bytes"),
    );
    assert_eq!(counter_value, 42, "Counter should be initialized to 42");

    tracing::info!("✓ Counter initialized successfully to {}", counter_value);
}

#[test]
#[ignore] // Requires counter program to be built first
fn test_counter_increment() {
    // Initialize tracing
    let _ = tracing_subscriber::fmt::try_init();

    // Load the counter program binary
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let counter_so_path = manifest_dir
        .parent()
        .unwrap()
        .join("examples/counter-program/target/deploy/counter_program.so");

    if !counter_so_path.exists() {
        panic!(
            "Counter program not found. Run 'cargo build-sbf' in examples/counter-program first"
        );
    }

    let bytecode = std::fs::read(&counter_so_path).expect("Failed to read counter program");

    // Create program ID and counter account
    let program_id = Pubkey::new_unique();
    let counter_key = Pubkey::new_unique();

    // Initialize counter account with value 10
    let initial_value: u64 = 10;
    let mut initial_data = initial_value.to_le_bytes().to_vec();

    let counter_account = AccountState::new(
        counter_key,
        1000,
        initial_data.clone(),
        program_id,
        false,
        0,
    );

    // First, initialize the counter to 10
    let instruction_data = serialize_initialize_counter(10);

    let mut context =
        TransactionContext::single_account(program_id, counter_account.clone(), instruction_data);

    trace_program_with_accounts(&bytecode, &mut context).expect("Failed to initialize counter");

    // Now increment the counter
    let instruction_data = serialize_increment_counter();

    // Get the account state after initialization
    let initialized_account = context.accounts[0].clone();

    let mut context =
        TransactionContext::single_account(program_id, initialized_account, instruction_data);

    let trace =
        trace_program_with_accounts(&bytecode, &mut context).expect("Failed to increment counter");

    // Verify execution succeeded
    assert_eq!(
        trace.final_registers.regs[0], 0,
        "Program should return 0 for success"
    );

    // Verify the counter was incremented from 10 to 11
    let account_change = &trace.account_states[0];
    let final_value = u64::from_le_bytes(
        account_change.after.data[0..8]
            .try_into()
            .expect("Account data should be at least 8 bytes"),
    );

    assert_eq!(final_value, 11, "Counter should be incremented to 11");

    tracing::info!(
        "✓ Counter incremented successfully: 10 → {}",
        final_value
    );
}
