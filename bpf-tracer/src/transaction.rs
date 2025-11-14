//! Transaction context for Solana account-based execution
//!
//! This module implements Solana's transaction account serialization format,
//! allowing BPF programs to access accounts via AccountInfo structures.

use crate::trace::AccountState;
use crate::Result;
use solana_pubkey::Pubkey;
use std::mem;

/// Transaction context holding accounts for BPF program execution
///
/// Manages account data and provides serialization in Solana's format
/// for passing to BPF programs via the input parameter.
#[derive(Debug, Clone)]
pub struct TransactionContext {
    /// Program ID executing this transaction
    pub program_id: Pubkey,
    /// Accounts accessible to the program
    pub accounts: Vec<AccountState>,
    /// Instruction data to pass to the program
    pub instruction_data: Vec<u8>,
}

impl TransactionContext {
    /// Create a new transaction context
    pub fn new(program_id: Pubkey, accounts: Vec<AccountState>, instruction_data: Vec<u8>) -> Self {
        Self {
            program_id,
            accounts,
            instruction_data,
        }
    }

    /// Create a simple transaction context with a single account
    ///
    /// Useful for simple programs like the counter that only need one account.
    pub fn single_account(
        program_id: Pubkey,
        account: AccountState,
        instruction_data: Vec<u8>,
    ) -> Self {
        Self::new(program_id, vec![account], instruction_data)
    }

    /// Serialize accounts and instruction data in Solana's format
    ///
    /// Format (based on solana-program v1.18 entrypoint.rs):
    /// - u64: number of accounts
    /// - For each account:
    ///   - u8: dup_info (NON_DUP_MARKER = 255)
    ///   - u8: is_signer
    ///   - u8: is_writable
    ///   - u8: executable
    ///   - u32: original_data_len (for realloc validation)
    ///   - 32 bytes: pubkey
    ///   - 32 bytes: owner
    ///   - u64: lamports (value, accessed as pointer by program)
    ///   - u64: data length
    ///   - data_len bytes: account data
    ///   - MAX_PERMITTED_DATA_INCREASE bytes: realloc padding
    ///   - alignment padding to BPF_ALIGN_OF_U128
    ///   - u64: rent_epoch
    /// - u64: instruction data length
    /// - instruction_data_len bytes: instruction data
    /// - 32 bytes: program_id
    pub fn serialize(&self) -> Result<Vec<u8>> {
        const NON_DUP_MARKER: u8 = 255;
        const MAX_PERMITTED_DATA_INCREASE: usize = 10 * 1024;
        const BPF_ALIGN_OF_U128: usize = 8;

        let mut buffer = Vec::new();

        // Number of accounts (u64)
        buffer.extend_from_slice(&(self.accounts.len() as u64).to_le_bytes());

        // Serialize each account
        for account in &self.accounts {
            // dup_info (u8) - NON_DUP_MARKER = 255 for non-duplicate accounts
            buffer.push(NON_DUP_MARKER);

            // is_signer (u8) - 0 for demo purposes
            buffer.push(0u8);

            // is_writable (u8) - 1 for writable accounts
            buffer.push(1u8);

            // executable (u8)
            buffer.push(account.executable as u8);

            // original_data_len (u32) - used for realloc validation
            buffer.extend_from_slice(&(account.data.len() as u32).to_le_bytes());

            // pubkey (32 bytes)
            buffer.extend_from_slice(account.pubkey.as_ref());

            // owner (32 bytes)
            buffer.extend_from_slice(account.owner.as_ref());

            // lamports (u64) - the program accesses this via pointer
            buffer.extend_from_slice(&account.lamports.to_le_bytes());

            // data length (u64)
            buffer.extend_from_slice(&(account.data.len() as u64).to_le_bytes());

            // data bytes
            buffer.extend_from_slice(&account.data);

            // MAX_PERMITTED_DATA_INCREASE padding (10,240 bytes)
            buffer.extend_from_slice(&vec![0u8; MAX_PERMITTED_DATA_INCREASE]);

            // Alignment padding to BPF_ALIGN_OF_U128 (8 bytes)
            let total_len = account.data.len() + MAX_PERMITTED_DATA_INCREASE;
            let align_offset = total_len % BPF_ALIGN_OF_U128;
            if align_offset != 0 {
                let padding = BPF_ALIGN_OF_U128 - align_offset;
                buffer.extend_from_slice(&vec![0u8; padding]);
            }

            // rent_epoch (u64)
            buffer.extend_from_slice(&account.rent_epoch.to_le_bytes());
        }

        // Instruction data length (u64)
        buffer.extend_from_slice(&(self.instruction_data.len() as u64).to_le_bytes());

        // Instruction data bytes
        buffer.extend_from_slice(&self.instruction_data);

        // program_id (32 bytes)
        buffer.extend_from_slice(self.program_id.as_ref());

        Ok(buffer)
    }

    /// Deserialize account data after program execution
    ///
    /// Updates the account states with any changes made by the program.
    /// This is simpler than full deserialization - we just extract the
    /// account data portions that may have been modified.
    pub fn deserialize_accounts(&mut self, buffer: &[u8]) -> Result<()> {
        const MAX_PERMITTED_DATA_INCREASE: usize = 10 * 1024;
        const BPF_ALIGN_OF_U128: usize = 8;

        let mut offset = 0;

        // Skip number of accounts (u64)
        offset += mem::size_of::<u64>();

        // Deserialize each account
        for account in &mut self.accounts {
            // Skip dup_info, is_signer, is_writable, executable (4 bytes)
            offset += 4;

            // Skip original_data_len (u32)
            offset += mem::size_of::<u32>();

            // Skip pubkey (32 bytes)
            offset += 32;

            // Skip owner (32 bytes)
            offset += 32;

            // Read lamports (u64)
            if offset + mem::size_of::<u64>() > buffer.len() {
                return Err(anyhow::anyhow!("Buffer too short for lamports"));
            }
            let lamports = u64::from_le_bytes(
                buffer[offset..offset + mem::size_of::<u64>()]
                    .try_into()
                    .unwrap(),
            );
            account.lamports = lamports;
            offset += mem::size_of::<u64>();

            // Read data length (u64)
            if offset + mem::size_of::<u64>() > buffer.len() {
                return Err(anyhow::anyhow!("Buffer too short for data length"));
            }
            let data_len = u64::from_le_bytes(
                buffer[offset..offset + mem::size_of::<u64>()]
                    .try_into()
                    .unwrap(),
            ) as usize;
            offset += mem::size_of::<u64>();

            // Read data bytes
            if offset + data_len > buffer.len() {
                return Err(anyhow::anyhow!("Buffer too short for account data"));
            }
            account.data = buffer[offset..offset + data_len].to_vec();
            offset += data_len;

            // Skip MAX_PERMITTED_DATA_INCREASE padding
            offset += MAX_PERMITTED_DATA_INCREASE;

            // Skip BPF_ALIGN_OF_U128 alignment padding
            let total_len = data_len + MAX_PERMITTED_DATA_INCREASE;
            let align_offset = total_len % BPF_ALIGN_OF_U128;
            if align_offset != 0 {
                let padding = BPF_ALIGN_OF_U128 - align_offset;
                offset += padding;
            }

            // Read rent_epoch (u64)
            if offset + mem::size_of::<u64>() > buffer.len() {
                return Err(anyhow::anyhow!("Buffer too short for rent_epoch"));
            }
            let rent_epoch = u64::from_le_bytes(
                buffer[offset..offset + mem::size_of::<u64>()]
                    .try_into()
                    .unwrap(),
            );
            account.rent_epoch = rent_epoch;
            offset += mem::size_of::<u64>();
        }

        Ok(())
    }

    /// Get a snapshot of current account states
    pub fn snapshot_accounts(&self) -> Vec<AccountState> {
        self.accounts.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_empty() {
        let program_id = Pubkey::new_unique();
        let ctx = TransactionContext::new(program_id, vec![], vec![]);

        let buffer = ctx.serialize().unwrap();

        // Should have: num_accounts (8) + instruction_data_len (8) + program_id (32)
        assert!(buffer.len() >= 48);

        // First 8 bytes should be 0 (no accounts)
        assert_eq!(u64::from_le_bytes(buffer[0..8].try_into().unwrap()), 0);
    }

    #[test]
    fn test_serialize_single_account() {
        let program_id = Pubkey::new_unique();
        let account_key = Pubkey::new_unique();

        let account = AccountState::new(
            account_key,
            1000,           // lamports
            vec![1, 2, 3],  // data
            program_id,     // owner
            false,          // executable
            0,              // rent_epoch
        );

        let instruction_data = vec![0x01, 0x00, 0x00, 0x00]; // Some instruction
        let ctx = TransactionContext::single_account(program_id, account, instruction_data);

        let buffer = ctx.serialize().unwrap();

        // Should contain serialized account data
        assert!(buffer.len() > 100); // At least space for metadata + data

        // First 8 bytes should be 1 (one account)
        assert_eq!(u64::from_le_bytes(buffer[0..8].try_into().unwrap()), 1);
    }

    #[test]
    fn test_roundtrip_account_data() {
        let program_id = Pubkey::new_unique();
        let account_key = Pubkey::new_unique();

        let account = AccountState::new(
            account_key,
            1000,
            vec![42, 0, 0, 0, 0, 0, 0, 0], // u64 counter = 42
            program_id,
            false,
            0,
        );

        let mut ctx = TransactionContext::single_account(program_id, account.clone(), vec![]);

        let buffer = ctx.serialize().unwrap();

        // Simulate program modifying the data
        let mut modified_buffer = buffer.clone();

        // Find the data section and modify it (this is simplified - real programs would do this)
        // Just verify we can deserialize after serialization
        ctx.deserialize_accounts(&modified_buffer).unwrap();

        // Account data should be preserved
        assert_eq!(ctx.accounts[0].pubkey, account.pubkey);
        assert_eq!(ctx.accounts[0].lamports, account.lamports);
    }

    #[test]
    fn test_multiple_accounts() {
        let program_id = Pubkey::new_unique();

        let accounts = vec![
            AccountState::new(
                Pubkey::new_unique(),
                1000,
                vec![1, 2, 3],
                program_id,
                false,
                0,
            ),
            AccountState::new(
                Pubkey::new_unique(),
                2000,
                vec![4, 5, 6, 7],
                program_id,
                false,
                0,
            ),
        ];

        let ctx = TransactionContext::new(program_id, accounts, vec![]);
        let buffer = ctx.serialize().unwrap();

        // Should have 2 accounts
        assert_eq!(u64::from_le_bytes(buffer[0..8].try_into().unwrap()), 2);
    }
}
