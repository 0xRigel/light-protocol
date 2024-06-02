use account_compression::program::AccountCompression;
use anchor_lang::prelude::*;

use crate::{
    invoke::sol_compression::COMPRESSED_SOL_PDA_SEED,
    sdk::{
        accounts::{InvokeAccounts, SignerAccounts},
        compressed_account::{CompressedAccount, PackedCompressedAccountWithMerkleContext},
    },
};

use super::processor::CompressedProof;

/// These are the base accounts additionally Merkle tree and queue accounts are required.
/// These additional accounts are passed as remaining accounts.
/// 1 Merkle tree for each input compressed account one queue and Merkle tree account each for each output compressed account.
#[derive(Accounts)]
pub struct InvokeInstruction<'info> {
    #[account(mut)]
    pub fee_payer: Signer<'info>,
    pub authority: Signer<'info>,
    /// CHECK: this account
    #[account(
    seeds = [&crate::ID.to_bytes()], bump, seeds::program = &account_compression::ID,
    )]
    pub registered_program_pda:
        Account<'info, account_compression::instructions::register_program::RegisteredProgram>,
    /// CHECK: this account
    pub noop_program: UncheckedAccount<'info>,
    /// CHECK: this account in psp account compression program
    #[account(seeds = [b"cpi_authority"], bump)]
    pub account_compression_authority: UncheckedAccount<'info>,
    /// CHECK: this account in psp account compression program
    pub account_compression_program: Program<'info, AccountCompression>,
    #[account(
        mut,
        seeds = [COMPRESSED_SOL_PDA_SEED], bump
    )]
    pub compressed_sol_pda: Option<UncheckedAccount<'info>>,
    #[account(mut)]
    pub compression_recipient: Option<UncheckedAccount<'info>>,
    pub system_program: Program<'info, System>,
}

impl<'info> SignerAccounts<'info> for InvokeInstruction<'info> {
    fn get_fee_payer(&self) -> &Signer<'info> {
        &self.fee_payer
    }

    fn get_authority(&self) -> &Signer<'info> {
        &self.authority
    }
}

impl<'info> InvokeAccounts<'info> for InvokeInstruction<'info> {
    fn get_registered_program_pda(
        &self,
    ) -> &Account<'info, account_compression::instructions::register_program::RegisteredProgram>
    {
        &self.registered_program_pda
    }

    fn get_noop_program(&self) -> &UncheckedAccount<'info> {
        &self.noop_program
    }

    fn get_account_compression_authority(&self) -> &UncheckedAccount<'info> {
        &self.account_compression_authority
    }

    fn get_account_compression_program(&self) -> &Program<'info, AccountCompression> {
        &self.account_compression_program
    }

    fn get_system_program(&self) -> &Program<'info, System> {
        &self.system_program
    }
    fn get_compressed_sol_pda(&self) -> Option<&UncheckedAccount<'info>> {
        self.compressed_sol_pda.as_ref()
    }
    fn get_compression_recipient(&self) -> Option<&UncheckedAccount<'info>> {
        self.compression_recipient.as_ref()
    }
}

#[derive(Debug, PartialEq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct InstructionDataInvoke {
    pub proof: Option<CompressedProof>,
    pub input_compressed_accounts_with_merkle_context:
        Vec<PackedCompressedAccountWithMerkleContext>,
    pub output_compressed_accounts: Vec<OutputCompressedAccountWithPackedContext>,
    pub relay_fee: Option<u64>,
    pub new_address_params: Vec<NewAddressParamsPacked>,
    pub compression_lamports: Option<u64>,
    pub is_compress: bool,
}

#[derive(Debug, PartialEq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct OutputCompressedAccountWithContext {
    pub compressed_account: CompressedAccount,
    pub merkle_tree: Pubkey,
}

#[derive(Debug, PartialEq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct OutputCompressedAccountWithPackedContext {
    pub compressed_account: CompressedAccount,
    pub merkle_tree_index: u8,
}

#[derive(Debug, PartialEq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct NewAddressParamsPacked {
    pub seed: Vec<u8>,
    pub address_queue_account_index: u8,
    pub address_merkle_tree_account_index: u8,
    pub address_merkle_tree_root_index: u16,
}

#[derive(Debug, PartialEq, Default, Clone, AnchorSerialize, AnchorDeserialize)]
pub struct NewAddressParams {
    pub seed: Vec<u8>,
    pub address_queue_pubkey: Pubkey,
    pub address_merkle_tree_pubkey: Pubkey,
    pub address_merkle_tree_root_index: u16,
}
