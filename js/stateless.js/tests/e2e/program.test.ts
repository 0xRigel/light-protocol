import { describe, it, expect, assert, beforeAll } from 'vitest';
import {
  CompressedProof_IdlType,
  Utxo,
  Utxo_IdlType,
  createUtxo,
} from '../../src/state';
import {
  PAYER_KEYPAIR,
  byteArrayToKeypair,
} from '../../src/test-utils/init-accounts';

import {
  PublicKey,
  Connection,
  TransactionMessage,
  VersionedTransaction,
  TransactionConfirmationStrategy,
  Keypair,
} from '@solana/web3.js';
import { BN } from '@coral-xyz/anchor';
import { createExecuteCompressedInstruction } from '../../src/instruction/pack-nop-instruction';
import { defaultTestStateTreeAccounts } from '../../src/constants';
import {
  buildAndSignTx,
  confirmTx,
  getMockRpc,
  sendAndConfirmTx,
} from '../../src/test-utils';

describe('Program test', () => {
  const keys = defaultTestStateTreeAccounts();
  const merkleTree = keys.merkleTree;
  const payer = byteArrayToKeypair([
    122, 239, 192, 18, 21, 29, 237, 120, 104, 95, 247, 150, 181, 218, 207, 60,
    158, 110, 200, 246, 74, 226, 30, 223, 142, 138, 133, 194, 30, 254, 132, 236,
    227, 130, 162, 184, 215, 227, 81, 211, 134, 73, 118, 71, 219, 163, 243, 41,
    118, 21, 155, 87, 11, 53, 153, 130, 178, 126, 151, 86, 225, 36, 251, 130,
  ]);
  const bob = Keypair.generate();
  const connection = new Connection('http://localhost:8899', 'confirmed');

  beforeAll(async () => {
    const sig = await connection.requestAirdrop(payer.publicKey, 2e9);
    await confirmTx(connection, sig);
  });

  // Note:
  // We don't compress SOL yet, therefore cannot spend utxos with value yet.
  // TODO: add one run with with inputUtxo where lamports: 0
  it('should send .5 sol from alice to bob, with .5 change', async () => {
    const in_utxos: Utxo_IdlType[] = [];
    const out_utxos: Utxo[] = [
      {
        owner: bob.publicKey,
        lamports: new BN(0),
        data: null,
        address: null,
      },
      {
        owner: payer.publicKey,
        lamports: new BN(0),
        data: null,
        address: null,
      },
    ];

    const proof_mock: CompressedProof_IdlType = {
      a: Array.from({ length: 32 }, () => 0),
      b: Array.from({ length: 64 }, () => 0),
      c: Array.from({ length: 32 }, () => 0),
    };
    // const rpc = await getMockRpc(connection);
    // const proof = await rpc.getValidityProof(
    //   inUtxos.map((utxo) => utxo.merkleContext.hash as BN),
    // );

    const ix = await createExecuteCompressedInstruction(
      payer.publicKey,
      in_utxos,
      out_utxos,
      [],
      [],
      [merkleTree, merkleTree],
      [],
      proof_mock,
    );
    const ixs = [ix];

    /// Send
    const { blockhash } = await connection.getLatestBlockhash();
    const signedTx = buildAndSignTx(ixs, payer, blockhash);
    await sendAndConfirmTx(connection, signedTx);

    /// Assert emitted events
    const mockRpc = await getMockRpc(connection);
    const indexedEvents = await mockRpc.getParsedEvents();

    assert.equal(indexedEvents.length, 1);
    assert.equal(indexedEvents[0].inUtxos.length, 0);
    assert.equal(indexedEvents[0].outUtxos.length, 2);
    assert.equal(Number(indexedEvents[0].outUtxos[0].lamports), 0);
    assert.equal(Number(indexedEvents[0].outUtxos[1].lamports), 0);
    assert.equal(
      indexedEvents[0].outUtxos[0].owner.toBase58(),
      bob.publicKey.toBase58(),
    );
    assert.equal(
      indexedEvents[0].outUtxos[1].owner.toBase58(),
      payer.publicKey.toBase58(),
    );
    assert.equal(indexedEvents[0].outUtxos[0].data, null);
    assert.equal(indexedEvents[0].outUtxos[1].data, null);
  });

  /// TODO: enable test after refactor for packInstruction() is complete
  it.skip('should build ix and send to chain successfully', async () => {
    const keys = defaultTestStateTreeAccounts();
    const merkleTree = keys.merkleTree; /// TODO: replace with inited mt
    const queue = keys.nullifierQueue; /// TODO: replace with inited queue
    const payer = PAYER_KEYPAIR;

    const recipient = PublicKey.unique();
    const inputState: Utxo[] = [
      //   addMerkleContextToUtxo(
      //     createUtxo(payer.publicKey, 1_000_000_000n),
      //     0n,
      //     merkleTree,
      //     0,
      //     queue
      //   ),
    ];
    const outputState = [
      //   createUtxo(recipient, 120_000_000n),
      //   createUtxo(payer.publicKey, 880_000_000n),
      createUtxo(recipient, 0),
      createUtxo(payer.publicKey, 0),
    ];
    // const mockProof = placeholderValidityProof();
    const mockProof: CompressedProof_IdlType = {
      a: Array.from({ length: 32 }, (_, i) => i),
      b: Array.from({ length: 64 }, (_, i) => i),
      c: Array.from({ length: 32 }, (_, i) => i),
    };

    const ix = await createExecuteCompressedInstruction(
      payer.publicKey,
      inputState,
      outputState,
      [], //[merkleTree],
      [], // [queue],
      [merkleTree],
      [],
      mockProof,
    );

    const ixs = [ix];
    const connection = new Connection('http://localhost:8899', 'confirmed');

    const { blockhash, lastValidBlockHeight } =
      await connection.getLatestBlockhash();
    const balancePayer = await connection.getBalance(payer.publicKey);
    const balanceRecipient = await connection.getBalance(recipient);
    console.log('balance', balancePayer, balanceRecipient);

    const sig = await connection.requestAirdrop(payer.publicKey, 2e9);

    const transactionConfirmationStrategy: TransactionConfirmationStrategy = {
      signature: sig,
      blockhash,
      lastValidBlockHeight,
    };
    console.log('confirming...', sig);
    await connection.confirmTransaction(
      transactionConfirmationStrategy,
      'confirmed',
    );
    console.log('sig', sig, 'payer', payer.publicKey.toBase58());
    const balancePayerAfterAirdrop = await connection.getBalance(
      payer.publicKey,
      'confirmed',
    );
    console.log('balancePayerAfterAirdrop', balancePayerAfterAirdrop);

    // throw new Error("stop here");
    const messageV0 = new TransactionMessage({
      payerKey: payer.publicKey,
      recentBlockhash: blockhash,
      instructions: ixs,
    }).compileToV0Message();

    const tx = new VersionedTransaction(messageV0);
    tx.message.compiledInstructions[0].accountKeyIndexes.forEach((index, _) => {
      console.log(
        `Account ${index}: ${tx.message.staticAccountKeys[
          index
        ].toBase58()} - Signer: ${tx.message.isAccountSigner(index)}`,
      );
    });
    tx.sign([payer]);

    console.log('tx', tx.signatures, '\n', tx.message.getAccountKeys());
    const txid = await connection.sendTransaction(tx);

    console.log(
      `https://explorer.solana.com/tx/${txid}?cluster=custom&customUrl=http%3A%2F%2Flocalhost%3A8899`,
    );
    expect(txid).toBeTruthy();
  });
});
