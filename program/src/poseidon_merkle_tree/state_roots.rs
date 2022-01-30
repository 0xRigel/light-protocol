use solana_program::{
    account_info::AccountInfo,
    msg,
    program_error::ProgramError,
    program_pack::{IsInitialized, Pack, Sealed},
    pubkey::Pubkey,
};

use arrayref::{array_ref, array_refs};
use crate::utils::init_bytes18::MERKLE_TREE_ACC_BYTES_ARRAY;

#[derive(Clone, Debug)]
pub struct MerkleTreeRoots {
    pub is_initialized: bool,
    pub roots: Vec<u8>,
    pub root_history_size: u64,
}

impl Sealed for MerkleTreeRoots {}
impl IsInitialized for MerkleTreeRoots {
    fn is_initialized(&self) -> bool {
        self.is_initialized
    }
}

impl Pack for MerkleTreeRoots {
    const LEN: usize = 16657;

    fn unpack_from_slice(input: &[u8]) -> Result<Self, ProgramError> {
        let input = array_ref![input, 0, MerkleTreeRoots::LEN];

        let (
            is_initialized,
            _levels,
            _filled_subtrees,
            _current_root_index,
            _next_index,
            root_history_size,
            //609
            roots,
            //18137
            _unused_remainder,
        ) = array_refs![input, 1, 8, 576, 8, 8, 8, 16000, 48];

        if is_initialized[0] != 1u8 {
            msg!("Merkle Tree is not initialized");
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(MerkleTreeRoots {
            is_initialized: true,
            roots: roots.to_vec(),
            root_history_size: u64::from_le_bytes(*root_history_size),
        })
    }
    fn pack_into_slice(&self, _dst: &mut [u8]) {
        //is not meant to be called since this structs purpose is to solely unpack roots
        //to check for the existence of one root
    }
}

pub fn check_root_hash_exists(
    account_main: &AccountInfo,
    root_bytes: &Vec<u8>,
    program_id: &Pubkey,
    merkle_tree_index: u8
) -> Result<u8, ProgramError> {
    let account_main_data = MerkleTreeRoots::unpack(&account_main.data.borrow()).unwrap();
    msg!("merkletree acc key: {:?}", *account_main);
    msg!(
        "merkletree acc key to check: {:?}",
        solana_program::pubkey::Pubkey::new(&MERKLE_TREE_ACC_BYTES_ARRAY[merkle_tree_index as usize].0)
    );

    if *account_main.key != solana_program::pubkey::Pubkey::new(&MERKLE_TREE_ACC_BYTES_ARRAY[merkle_tree_index as usize].0) {
        msg!("merkle tree account pubkey is incorrect");
        return Err(ProgramError::IllegalOwner);
    }

    if *account_main.owner != *program_id {
        msg!("merkle tree account owner is incorrect");
        return Err(ProgramError::IllegalOwner);
    }

    if account_main_data.root_history_size > 593 {
        msg!("root history size too large");
        return Err(ProgramError::InvalidAccountData);
    }
    msg!("looking for root {:?}", *root_bytes);
    let found_root;
    let mut i = 0;
    let mut counter = 0;
    loop {
        if account_main_data.roots[i..i + 32] == *root_bytes {
            msg!("found root hash index {}", counter);
            found_root = 1u8;
            break;
        }

        if counter % 10 == 0 {
            msg!("{}", counter);
        }
        i += 32;
        counter += 1;
        if counter == account_main_data.root_history_size {
            msg!("did not find root");
            //panic!("did not find root");
            return Err(ProgramError::InvalidAccountData);
            // found_root = 0;
            // break;
        }
    }
    Ok(found_root)
}
