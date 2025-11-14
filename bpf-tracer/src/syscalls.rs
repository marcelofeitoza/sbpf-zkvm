//! Solana syscall implementations for BPF VM
//!
//! This module implements Solana syscalls that BPF programs can call.
//! For zkVM purposes, these are mostly stubs that allow programs to execute
//! without errors, while we focus on capturing execution traces and account states.

use crate::TracerContext;
use solana_sbpf::{
    declare_builtin_function,
    error::EbpfError,
    memory_region::{AccessType, MemoryMapping},
};
use std::str::from_utf8;

declare_builtin_function!(
    /// sol_log: Log a string message
    ///
    /// Used by the msg! macro in Solana programs.
    /// For zkVM, we just log to tracing and return success.
    SyscallLog,
    fn rust(
        _context_object: &mut TracerContext,
        message_addr: u64,
        message_len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        if message_len == 0 {
            return Ok(0);
        }

        // Map the message from VM memory
        let host_addr: Result<u64, EbpfError> =
            memory_mapping.map(AccessType::Load, message_addr, message_len).into();
        let host_addr = host_addr?;

        // Read the message bytes
        let message_bytes = unsafe {
            std::slice::from_raw_parts(host_addr as *const u8, message_len as usize)
        };

        // Try to convert to UTF-8 string
        match from_utf8(message_bytes) {
            Ok(message) => {
                tracing::debug!("sol_log: {}", message);
            }
            Err(_) => {
                tracing::debug!("sol_log: <non-UTF8 message>");
            }
        }

        Ok(0)
    }
);

declare_builtin_function!(
    /// sol_log_64: Log up to 5 u64 values
    ///
    /// Used for logging numeric values in Solana programs.
    SyscallLog64,
    fn rust(
        _context_object: &mut TracerContext,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        tracing::debug!("sol_log_64: {}, {}, {}, {}, {}", arg1, arg2, arg3, arg4, arg5);
        Ok(0)
    }
);

declare_builtin_function!(
    /// sol_memcpy_: Memory copy operation
    ///
    /// Copies memory from src to dst. Required by some Solana programs.
    SyscallMemcpy,
    fn rust(
        _context_object: &mut TracerContext,
        dst_addr: u64,
        src_addr: u64,
        len: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        if len == 0 {
            return Ok(0);
        }

        // Map source and destination memory
        let src_host_addr: Result<u64, EbpfError> =
            memory_mapping.map(AccessType::Load, src_addr, len).into();
        let src_host_addr = src_host_addr?;

        let dst_host_addr: Result<u64, EbpfError> =
            memory_mapping.map(AccessType::Store, dst_addr, len).into();
        let dst_host_addr = dst_host_addr?;

        // Copy memory
        unsafe {
            std::ptr::copy_nonoverlapping(
                src_host_addr as *const u8,
                dst_host_addr as *mut u8,
                len as usize,
            );
        }

        Ok(0)
    }
);

declare_builtin_function!(
    /// sol_memset_: Memory set operation
    ///
    /// Sets memory to a value. Required by some Solana programs.
    SyscallMemset,
    fn rust(
        _context_object: &mut TracerContext,
        dst_addr: u64,
        value: u64,
        len: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        if len == 0 {
            return Ok(0);
        }

        // Map destination memory
        let dst_host_addr: Result<u64, EbpfError> =
            memory_mapping.map(AccessType::Store, dst_addr, len).into();
        let dst_host_addr = dst_host_addr?;

        // Set memory
        unsafe {
            std::ptr::write_bytes(dst_host_addr as *mut u8, value as u8, len as usize);
        }

        Ok(0)
    }
);

declare_builtin_function!(
    /// sol_memmove_: Memory move operation (overlapping regions allowed)
    ///
    /// Like memcpy but handles overlapping memory regions.
    SyscallMemmove,
    fn rust(
        _context_object: &mut TracerContext,
        dst_addr: u64,
        src_addr: u64,
        len: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        if len == 0 {
            return Ok(0);
        }

        // Map source and destination memory
        let src_host_addr: Result<u64, EbpfError> =
            memory_mapping.map(AccessType::Load, src_addr, len).into();
        let src_host_addr = src_host_addr?;

        let dst_host_addr: Result<u64, EbpfError> =
            memory_mapping.map(AccessType::Store, dst_addr, len).into();
        let dst_host_addr = dst_host_addr?;

        // Copy memory (allows overlapping)
        unsafe {
            std::ptr::copy(
                src_host_addr as *const u8,
                dst_host_addr as *mut u8,
                len as usize,
            );
        }

        Ok(0)
    }
);

declare_builtin_function!(
    /// sol_memcmp_: Memory compare operation
    ///
    /// Compares two memory regions. Returns 0 if equal.
    SyscallMemcmp,
    fn rust(
        _context_object: &mut TracerContext,
        addr1: u64,
        addr2: u64,
        len: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        if len == 0 {
            return Ok(0);
        }

        // Map both memory regions
        let host_addr1: Result<u64, EbpfError> =
            memory_mapping.map(AccessType::Load, addr1, len).into();
        let host_addr1 = host_addr1?;

        let host_addr2: Result<u64, EbpfError> =
            memory_mapping.map(AccessType::Load, addr2, len).into();
        let host_addr2 = host_addr2?;

        // Compare memory
        let result = unsafe {
            let slice1 = std::slice::from_raw_parts(host_addr1 as *const u8, len as usize);
            let slice2 = std::slice::from_raw_parts(host_addr2 as *const u8, len as usize);
            slice1.cmp(slice2) as i32
        };

        // Write result to memory if result_addr is provided
        if result_addr != 0 {
            let result_host_addr: Result<u64, EbpfError> =
                memory_mapping.map(AccessType::Store, result_addr, 4).into();
            let result_host_addr = result_host_addr?;
            unsafe {
                *(result_host_addr as *mut i32) = result;
            }
        }

        Ok(0)
    }
);

declare_builtin_function!(
    /// abort: Program abort
    ///
    /// Called when a program panics or encounters an unrecoverable error.
    /// For zkVM, we log the abort and return an error.
    SyscallAbort,
    fn rust(
        _context_object: &mut TracerContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        tracing::error!("Program called abort()");
        Err("Program aborted".into())
    }
);

/// Register all Solana syscalls with the BPF program loader
///
/// This function registers the minimal set of syscalls needed for
/// Solana programs to execute in the zkVM tracer.
pub fn register_syscalls(
    loader: &mut solana_sbpf::program::BuiltinProgram<TracerContext>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Logging syscalls
    loader.register_function("sol_log_", SyscallLog::vm)?;
    loader.register_function("sol_log_64_", SyscallLog64::vm)?;

    // Memory operation syscalls
    loader.register_function("sol_memcpy_", SyscallMemcpy::vm)?;
    loader.register_function("sol_memset_", SyscallMemset::vm)?;
    loader.register_function("sol_memmove_", SyscallMemmove::vm)?;
    loader.register_function("sol_memcmp_", SyscallMemcmp::vm)?;

    // Runtime syscalls
    loader.register_function("abort", SyscallAbort::vm)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sbpf::{
        aligned_memory::AlignedMemory,
        ebpf,
        memory_region::{MemoryMapping, MemoryRegion},
        vm::Config,
    };

    #[test]
    fn test_syscall_log64() {
        let config = Config::default();
        let mut context = TracerContext::new(10000);
        let regions: Vec<MemoryRegion> = vec![];
        let mut memory_mapping =
            MemoryMapping::new(regions, &config, solana_sbpf::program::SBPFVersion::V2).unwrap();

        let result = SyscallLog64::rust(
            &mut context,
            1,
            2,
            3,
            4,
            5,
            &mut memory_mapping,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_syscall_memcpy() {
        let config = Config::default();
        let mut context = TracerContext::new(10000);

        // Create test memory
        let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(1024);
        let data = b"Hello, world!";
        heap.as_slice_mut()[0..data.len()].copy_from_slice(data);

        let regions: Vec<MemoryRegion> = vec![
            MemoryRegion::new_writable(heap.as_slice_mut(), ebpf::MM_HEAP_START),
        ];
        let mut memory_mapping =
            MemoryMapping::new(regions, &config, solana_sbpf::program::SBPFVersion::V2).unwrap();

        // Copy from offset 0 to offset 100
        let result = SyscallMemcpy::rust(
            &mut context,
            ebpf::MM_HEAP_START + 100,
            ebpf::MM_HEAP_START,
            data.len() as u64,
            0,
            0,
            &mut memory_mapping,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        // Verify the copy
        let copied = &heap.as_slice()[100..100 + data.len()];
        assert_eq!(copied, data);
    }
}
