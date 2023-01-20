use crate::state::TwoLeavesBytesPda;
use crate::utils::constants::LEAVES_SEED;
use crate::PreInsertedLeavesIndex;
use crate::RegisteredVerifier;
use anchor_lang::prelude::*;

#[derive(Accounts)]
#[instruction(
    leaf_left: [u8;32],
    leaf_right: [u8;32],
    encrypted_utxos: [u8;256],
    merkle_tree_pda_pubkey: Pubkey
)]
pub struct InsertTwoLeaves<'info> {
    /// CHECK:` should only be accessed by a registered verifier.
    #[account(mut, seeds=[program_id.to_bytes().as_ref()],bump,seeds::program=registered_verifier_pda.pubkey)]
    pub authority: Signer<'info>,
    // /// CHECK:` Leaves account should be checked by invoking verifier.
    #[account(init, seeds= [&leaf_left, LEAVES_SEED], bump, payer=authority, space= 8 + 3 * 32 + 256 + 8 + 8)]
    pub two_leaves_pda: Account<'info, TwoLeavesBytesPda>,
    #[account(mut, seeds= [&merkle_tree_pda_pubkey.to_bytes()], bump)]
    pub pre_inserted_leaves_index: Account<'info, PreInsertedLeavesIndex>,
    pub system_program: Program<'info, System>,
    #[account(seeds=[&registered_verifier_pda.pubkey.to_bytes()],  bump)]
    pub registered_verifier_pda: Account<'info, RegisteredVerifier>,
}

pub fn process_insert_two_leaves(
    ctx: Context<InsertTwoLeaves>,
    leaf_left: [u8; 32],
    leaf_right: [u8; 32],
    encrypted_utxos: [u8; 256],
    merkle_tree_pda_pubkey: Pubkey,
) -> Result<()> {
    //save leaves into pda account
    ctx.accounts.two_leaves_pda.node_left = leaf_left;
    ctx.accounts.two_leaves_pda.node_right = leaf_right;
    ctx.accounts.two_leaves_pda.left_leaf_index = ctx.accounts.pre_inserted_leaves_index.next_index;

    ctx.accounts.two_leaves_pda.merkle_tree_pubkey = merkle_tree_pda_pubkey;
    ctx.accounts.two_leaves_pda.encrypted_utxos = encrypted_utxos;

    // Increase next index by 2 because we're inserting 2 leaves at once.
    ctx.accounts.pre_inserted_leaves_index.next_index += 2;
    Ok(())
}
