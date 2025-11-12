//! Integration tests for the counter program
//!
//! Tests that the BPF counter program binary executes correctly

use std::fs;
use std::path::PathBuf;

/// Find the counter program .so file
fn find_counter_program() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let so_path = PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .join("examples/counter-program/target/sbf-solana-solana/release/counter_program.so");

    if !so_path.exists() {
        panic!(
            "Counter program binary not found at {:?}. \
             Run 'just build-bpf' to build the BPF program first.",
            so_path
        );
    }

    so_path
}

#[test]
#[ignore] // Requires counter program to be built first with 'just build-bpf'
fn test_counter_program_exists() {
    let so_path = find_counter_program();
    assert!(so_path.exists(), "Counter program .so should exist");

    let contents = fs::read(&so_path).expect("Failed to read .so file");
    assert!(!contents.is_empty(), "Counter program .so should not be empty");

    // Check ELF magic bytes
    assert_eq!(&contents[0..4], b"\x7fELF", "Should be a valid ELF file");
}

#[test]
#[ignore] // Requires counter program to be built first with 'just build-bpf'
fn test_counter_program_metadata() {
    let so_path = find_counter_program();
    let metadata = fs::metadata(&so_path).expect("Failed to get metadata");

    println!("Counter program size: {} bytes", metadata.len());
    assert!(
        metadata.len() < 10_000,
        "Counter program should be small (< 10KB)"
    );
}

// TODO: Add tests that actually execute the BPF program using solana-sbpf VM
// This requires implementing the VM wrapper in bpf-tracer first.
//
// Example test cases to implement later:
// - test_counter_increment_from_zero()
// - test_counter_increment_arbitrary_value()
// - test_counter_overflow()
// - test_counter_return_value()
