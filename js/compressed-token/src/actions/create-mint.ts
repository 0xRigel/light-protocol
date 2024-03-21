import {
    ConfirmOptions,
    Connection,
    Keypair,
    PublicKey,
    Signer,
    TransactionSignature,
} from '@solana/web3.js';
import { CompressedTokenProgram } from '../program';
import { MINT_SIZE } from '@solana/spl-token';
import { sendAndConfirmTx } from '@lightprotocol/stateless.js';
import { buildAndSignTx } from '@lightprotocol/stateless.js';
import { dedupeSigner } from './common';

/**
 * Create and initialize a new compressed token mint
 *
 * @param connection      Connection to use
 * @param payer           Payer of the transaction and initialization fees
 * @param mintAuthority   Account or multisig that will control minting. Is signer.
 * @param decimals        Location of the decimal place
 * @param keypair         Optional keypair, defaulting to a new random one
 * @param confirmOptions  Options for confirming the transaction
 *
 * @return Address of the new mint and the transaction signature
 */
export async function createMint(
    connection: Connection,
    payer: Signer,
    mintAuthority: Signer,
    decimals: number,
    keypair = Keypair.generate(),
    confirmOptions?: ConfirmOptions,
): Promise<{ mint: PublicKey; transactionSignature: TransactionSignature }> {
    const rentExemptBalance =
        await connection.getMinimumBalanceForRentExemption(MINT_SIZE);

    const ixs = await CompressedTokenProgram.createMint({
        feePayer: payer.publicKey,
        mint: keypair.publicKey,
        decimals,
        authority: mintAuthority.publicKey,
        freezeAuthority: null, // TODO: add feature
        rentExemptBalance,
    });

    const { blockhash } = await connection.getLatestBlockhash();

    const additionalSigners = dedupeSigner(payer, [mintAuthority, keypair]);

    const tx = buildAndSignTx(ixs, payer, blockhash, additionalSigners);

    const txId = await sendAndConfirmTx(connection, tx, confirmOptions);

    return { mint: keypair.publicKey, transactionSignature: txId };
}
