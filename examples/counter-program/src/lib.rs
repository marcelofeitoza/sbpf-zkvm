//! Counter Program - Minimal no_std Solana BPF Program
//!
//! This program increments a 64-bit counter value stored at a fixed memory location.
//! It's designed to be as simple as possible for ZK proving demonstration.
//!
//! Program logic:
//! 1. Read u64 counter value from memory address (passed in r1 register)
//! 2. Increment the value by 1
//! 3. Write the incremented value back to the same memory address
//! 4. Return success (0) in r0 register

#![no_std]
#![no_main]

use core::panic::PanicInfo;

/// Program entrypoint
///
/// # Arguments (passed via registers)
/// - r1: Pointer to counter value in memory (u64)
///
/// # Returns
/// - r0: 0 for success, non-zero for error
#[no_mangle]
pub unsafe extern "C" fn entrypoint(input: *mut u8) -> u64 {
    // Read the current counter value from memory
    // Input pointer (r1) points to a u64 counter value
    let counter_ptr = input as *mut u64;
    let current_value = core::ptr::read_volatile(counter_ptr);

    // Increment the counter
    let new_value = current_value.wrapping_add(1);

    // Write the new value back to memory
    core::ptr::write_volatile(counter_ptr, new_value);

    // Return success (0)
    0
}

/// Panic handler required for no_std
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_increment() {
        let mut counter: u64 = 42;
        let result = unsafe {
            entrypoint(&mut counter as *mut u64 as *mut u8)
        };

        assert_eq!(result, 0); // Success
        assert_eq!(counter, 43); // Incremented
    }

    #[test]
    fn test_counter_overflow() {
        let mut counter: u64 = u64::MAX;
        let result = unsafe {
            entrypoint(&mut counter as *mut u64 as *mut u8)
        };

        assert_eq!(result, 0); // Success
        assert_eq!(counter, 0); // Wrapped to 0
    }
}
