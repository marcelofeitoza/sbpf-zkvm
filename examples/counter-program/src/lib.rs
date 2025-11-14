//! Counter Program - Solana Program Example
//!
//! A simple counter program following official Solana program structure.
//! Demonstrates proper account handling, state management, and instruction processing.
//!
//! Based on: https://solana.com/docs/programs/rust/program-structure

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

/// Define the state stored in the counter account
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct CounterAccount {
    /// The current count value
    pub count: u64,
}

/// Instructions supported by the counter program
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum CounterInstruction {
    /// Initialize a counter account with an initial value
    ///
    /// Accounts expected:
    /// 0. `[writable]` Counter account to initialize
    InitializeCounter { initial_value: u64 },

    /// Increment the counter by 1
    ///
    /// Accounts expected:
    /// 0. `[writable]` Counter account to increment
    IncrementCounter,
}

// Declare the program entrypoint
entrypoint!(process_instruction);

/// Program entrypoint
///
/// # Arguments
/// * `program_id` - Public key of the program account
/// * `accounts` - Accounts required for the instruction
/// * `instruction_data` - Serialized instruction data
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("Counter program entrypoint");

    // Deserialize the instruction
    let instruction = CounterInstruction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Route to appropriate handler
    match instruction {
        CounterInstruction::InitializeCounter { initial_value } => {
            msg!("Instruction: InitializeCounter");
            initialize_counter(program_id, accounts, initial_value)
        }
        CounterInstruction::IncrementCounter => {
            msg!("Instruction: IncrementCounter");
            increment_counter(program_id, accounts)
        }
    }
}

/// Initialize a counter account with an initial value
fn initialize_counter(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    initial_value: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    // Get the counter account
    let counter_account = next_account_info(accounts_iter)?;

    // Verify the counter account is writable
    if !counter_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify the counter account is owned by this program
    if counter_account.owner != program_id {
        msg!("Counter account does not have the correct program id");
        return Err(ProgramError::IncorrectProgramId);
    }

    // Create the counter state
    let counter = CounterAccount {
        count: initial_value,
    };

    // Serialize and write to account data
    counter.serialize(&mut &mut counter_account.data.borrow_mut()[..])?;

    msg!("Counter initialized with value: {}", initial_value);
    Ok(())
}

/// Increment the counter by 1
fn increment_counter(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    // Get the counter account
    let counter_account = next_account_info(accounts_iter)?;

    // Verify the counter account is writable
    if !counter_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify the counter account is owned by this program
    if counter_account.owner != program_id {
        msg!("Counter account does not have the correct program id");
        return Err(ProgramError::IncorrectProgramId);
    }

    // Deserialize the current counter state
    let mut counter = CounterAccount::try_from_slice(&counter_account.data.borrow())?;

    msg!("Current counter value: {}", counter.count);

    // Increment the counter
    counter.count = counter.count.wrapping_add(1);

    msg!("New counter value: {}", counter.count);

    // Serialize and write back to account data
    counter.serialize(&mut &mut counter_account.data.borrow_mut()[..])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::clock::Epoch;
    use std::mem;

    #[test]
    fn test_initialize_counter() {
        let program_id = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let mut lamports = 0;
        let mut data = vec![0; mem::size_of::<CounterAccount>()];
        let owner = program_id;

        let account = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data,
            &owner,
            false,
            Epoch::default(),
        );

        let accounts = vec![account];

        // Create InitializeCounter instruction
        let instruction = CounterInstruction::InitializeCounter { initial_value: 42 };
        let instruction_data = instruction.try_to_vec().unwrap();

        // Process the instruction
        process_instruction(&program_id, &accounts, &instruction_data).unwrap();

        // Verify the counter was initialized
        let counter_account = CounterAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
        assert_eq!(counter_account.count, 42);
    }

    #[test]
    fn test_increment_counter() {
        let program_id = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let mut lamports = 0;
        let mut data = vec![0; mem::size_of::<CounterAccount>()];
        let owner = program_id;

        let account = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data,
            &owner,
            false,
            Epoch::default(),
        );

        let accounts = vec![account];

        // Initialize counter to 10
        let init_instruction = CounterInstruction::InitializeCounter { initial_value: 10 };
        let init_data = init_instruction.try_to_vec().unwrap();
        process_instruction(&program_id, &accounts, &init_data).unwrap();

        // Increment the counter
        let inc_instruction = CounterInstruction::IncrementCounter;
        let inc_data = inc_instruction.try_to_vec().unwrap();
        process_instruction(&program_id, &accounts, &inc_data).unwrap();

        // Verify the counter was incremented
        let counter_account = CounterAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
        assert_eq!(counter_account.count, 11);
    }

    #[test]
    fn test_counter_overflow() {
        let program_id = Pubkey::new_unique();
        let key = Pubkey::new_unique();
        let mut lamports = 0;
        let mut data = vec![0; mem::size_of::<CounterAccount>()];
        let owner = program_id;

        let account = AccountInfo::new(
            &key,
            false,
            true,
            &mut lamports,
            &mut data,
            &owner,
            false,
            Epoch::default(),
        );

        let accounts = vec![account];

        // Initialize counter to u64::MAX
        let init_instruction = CounterInstruction::InitializeCounter {
            initial_value: u64::MAX,
        };
        let init_data = init_instruction.try_to_vec().unwrap();
        process_instruction(&program_id, &accounts, &init_data).unwrap();

        // Increment the counter (should wrap to 0)
        let inc_instruction = CounterInstruction::IncrementCounter;
        let inc_data = inc_instruction.try_to_vec().unwrap();
        process_instruction(&program_id, &accounts, &inc_data).unwrap();

        // Verify the counter wrapped to 0
        let counter_account = CounterAccount::try_from_slice(&accounts[0].data.borrow()).unwrap();
        assert_eq!(counter_account.count, 0);
    }
}
