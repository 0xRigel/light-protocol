use crate::instructions::{check_and_insert_nullifier, create_and_check_account, token_transfer, check_external_amount};
use crate::poseidon_merkle_tree::processor::MerkleTreeProcessor;
use crate::poseidon_merkle_tree::state_roots::{check_root_hash_exists, MERKLE_TREE_ACC_BYTES};
use crate::state::ChecksAndTransferState;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    msg,
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
};
use std::convert::TryInto;

// Processor for deposit and withdraw logic.
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    current_instruction_index: usize,
) -> Result<(), ProgramError> {
    msg!("Entered process_instruction");

    let account = &mut accounts.iter();
    let signer_account = next_account_info(account)?;
    let tmp_storage_pda = next_account_info(account)?;
    let mut tmp_storage_pda_data = ChecksAndTransferState::unpack(&tmp_storage_pda.data.borrow())?;

    // Checks whether passed-in root exists in Merkle tree history array.
    // We do this check as soon as possible to avoid proof transaction invalidation for missing
    // root. Currently 500 roots are stored at once. After 500 transactions roots are overwritten.
    if current_instruction_index == 1 {
        let merkle_tree_pda = next_account_info(account)?;
        msg!(
            "Passed-in merkle_tree_pda pubkey: {:?}",
            *merkle_tree_pda.key
        );
        msg!(
            "Checks against hardcoded merkle_tree_pda pubkey: {:?}",
            solana_program::pubkey::Pubkey::new(&MERKLE_TREE_ACC_BYTES[..])
        );
        tmp_storage_pda_data.found_root = check_root_hash_exists(
            merkle_tree_pda,
            &tmp_storage_pda_data.root_hash,
            &program_id,
        )?;
    }
    // Checks and inserts nullifier pdas, two Merkle tree leaves (output utxo hashes),
    // and executes transaction, deposit or withdrawal.
    else if current_instruction_index == 1501 {
        //signers
        //temp acc
        let two_leaves_pda = next_account_info(account)?;
        let nullifier0_pda = next_account_info(account)?;
        let nullifier1_pda = next_account_info(account)?;
        let merkle_tree_pda = next_account_info(account)?;
        let merkle_tree_pda_token = next_account_info(account)?;
        let system_program_account = next_account_info(account)?;
        let token_program_account = next_account_info(account)?;
        let authority = next_account_info(account)?;
        let authority_seed = [7u8;32];
        let (expected_authority_pubkey, authority_bump_seed) = Pubkey::find_program_address(&[&authority_seed], program_id);

        if expected_authority_pubkey != *authority.key {
            msg!("Invalid passed-in authority.");
            return Err(ProgramError::InvalidArgument);
        }

        if *merkle_tree_pda.key != solana_program::pubkey::Pubkey::new(&MERKLE_TREE_ACC_BYTES) {
            msg!("Recipient has to be merkle tree account for deposit.");
            return Err(ProgramError::InvalidInstructionData);
        }

        msg!("Starting nullifier check.");
        tmp_storage_pda_data.found_nullifier = check_and_insert_nullifier(
            program_id,
            signer_account,
            nullifier0_pda,
            system_program_account,
            &tmp_storage_pda_data.proof_a_b_c_leaves_and_nullifiers[320..352],
        )?;
        msg!(
            "nullifier0_pda inserted {}",
            tmp_storage_pda_data.found_nullifier
        );

        tmp_storage_pda_data.found_nullifier = check_and_insert_nullifier(
            program_id,
            signer_account,
            nullifier1_pda,
            system_program_account,
            &tmp_storage_pda_data.proof_a_b_c_leaves_and_nullifiers[352..384],
        )?;
        msg!(
            "nullifier1_pda inserted {}",
            tmp_storage_pda_data.found_nullifier
        );

        msg!("Inserting new merkle root.");
        let mut merkle_tree_processor = MerkleTreeProcessor::new(Some(tmp_storage_pda), None)?;


        let (pub_amount_checked, relayer_fees) = check_external_amount(&tmp_storage_pda_data)?;
        let ext_amount =
            i64::from_le_bytes(tmp_storage_pda_data.ext_amount.clone().try_into().unwrap());

        if ext_amount != 0 {
            let user_pda_token = next_account_info(account)?;


            if ext_amount > 0 {

                msg!("Created two_leaves_pda successfully.");

                msg!("Deposited {}", pub_amount_checked);
                token_transfer(
                    token_program_account,
                    user_pda_token,
                    //two_leaves_pda
                    //destination,
                    merkle_tree_pda_token,
                    &authority,
                    &authority_seed[..],
                    &[authority_bump_seed],
                    pub_amount_checked,
                )?;

            } else if ext_amount < 0 {
                // let recipient_account = next_account_info(account)?;
                //
                // if *recipient_account.key
                //     != solana_program::pubkey::Pubkey::new(&tmp_storage_pda_data.to_address)
                // {
                //     msg!("Recipient has to be address specified in tx integrity hash.");
                //     return Err(ProgramError::InvalidInstructionData);
                // }
                let user_pda_token = next_account_info(account)?;
                let authority = next_account_info(account)?;

                if *user_pda_token.key
                    != solana_program::pubkey::Pubkey::new(&tmp_storage_pda_data.to_address)
                {
                    msg!("Recipient has to be address specified in tx integrity hash.");
                    return Err(ProgramError::InvalidInstructionData);
                }
                msg!("Creating two_leaves_pda.");
                create_and_check_account(
                    program_id,
                    signer_account,
                    two_leaves_pda,
                    system_program_account,
                    &tmp_storage_pda_data.proof_a_b_c_leaves_and_nullifiers[320..352],
                    &b"leaves"[..],
                    106u64, //bytes
                    0u64,   //lamports
                    true,   //rent_exempt
                )?;
                msg!("Created two_leaves_pda successfully.");

                token_transfer(
                    token_program_account,
                    merkle_tree_pda_token,
                    //two_leaves_pda
                    //destination,
                    user_pda_token,
                    &authority,
                    &authority_seed[..],
                    &[authority_bump_seed],
                    pub_amount_checked,
                )?;


            }
        }

        if relayer_fees > 0 {
            if Pubkey::new(&tmp_storage_pda_data.signing_address) != *signer_account.key {
                msg!("wrong relayer");
                return Err(ProgramError::InvalidArgument);
            }
            let relayer_pda_token = next_account_info(account)?;

            token_transfer(
                token_program_account,
                merkle_tree_pda_token,
                //destination,
                relayer_pda_token,
                &authority,
                &authority_seed[..],
                &[authority_bump_seed],
                relayer_fees,
            )?;
        }
        msg!("Creating two_leaves_pda.");
        create_and_check_account(
            program_id,
            signer_account,
            two_leaves_pda,
            system_program_account,
            &tmp_storage_pda_data.proof_a_b_c_leaves_and_nullifiers[320..352],
            &b"leaves"[..],
            106u64,                             //bytes
            0,                                  //lamports
            true,                               //rent_exempt
        )?;
        //insert Merkle root
        merkle_tree_processor.process_instruction(accounts)?;

    }

    tmp_storage_pda_data.current_instruction_index += 1;
    ChecksAndTransferState::pack_into_slice(
        &tmp_storage_pda_data,
        &mut tmp_storage_pda.data.borrow_mut(),
    );
    Ok(())
}
