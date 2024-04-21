import {
    ConnectionConfig,
    ParsedMessageAccount,
    ParsedTransactionWithMeta,
    PublicKey,
} from '@solana/web3.js';
import { LightWasm, WasmFactory } from '@lightprotocol/hasher.rs';
import {
    defaultStaticAccountsStruct,
    defaultTestStateTreeAccounts,
    CompressedProofWithContext,
    BN254,
    PublicTransactionEvent,
    Rpc,
    bn,
    negateAndCompressProof,
    parseEvents,
    parsePublicTransactionEventWithIdl,
    proofFromJsonStruct,
    toHex,
} from '@lightprotocol/stateless.js';

import { MerkleTree } from '../merkle-tree/merkle-tree';

export interface TestRpcConfig {
    /** Address of the state tree to index. Default: public default test state
     * tree */
    merkleTreeAddress?: PublicKey;
    /** Nullifier queue associated with merkleTreeAddress */
    nullifierQueueAddress?: PublicKey;
    /** Depth of state tree. Defaults to the public default test state tree depth */
    depth?: number;
    /** Log proof generation time */
    log?: boolean;
}

/**
 * Returns a mock RPC instance for use in unit tests.
 *
 * @param endpoint                RPC endpoint URL. Defaults to
 *                                'http://127.0.0.1:8899'.
 * @param proverEndpoint          Prover server endpoint URL. Defaults to
 *                                'http://localhost:3001'.
 * @param lightWasm               Wasm hasher instance.
 * @param merkleTreeAddress       Address of the merkle tree to index. Defaults
 *                                to the public default test state tree.
 * @param nullifierQueueAddress   Optional address of the associated nullifier
 *                                queue.
 * @param depth                   Depth of the merkle tree.
 * @param log                     Log proof generation time.
 */
export async function getTestRpc(
    endpoint: string = 'http://127.0.0.1:8899',
    compressionApiEndpoint: string = 'http://localhost:8784',
    proverEndpoint: string = 'http://localhost:3001',
    lightWasm?: LightWasm,
    merkleTreeAddress?: PublicKey,
    nullifierQueueAddress?: PublicKey,
    depth?: number,
    log = false,
) {
    lightWasm = lightWasm || (await WasmFactory.getInstance());

    const defaultAccounts = defaultTestStateTreeAccounts();

    return new TestRpc(
        endpoint,
        lightWasm,
        compressionApiEndpoint,
        proverEndpoint,
        undefined,
        {
            merkleTreeAddress: merkleTreeAddress || defaultAccounts.merkleTree,
            nullifierQueueAddress:
                nullifierQueueAddress || defaultAccounts.nullifierQueue,
            depth: depth || defaultAccounts.merkleTreeHeight,
            log,
        },
    );
}
/**
 * Simple mock rpc for unit tests that simulates the compression rpc interface.
 * Fetches, parses events and builds merkletree on-demand, i.e. it does not persist state.
 * Constraints:
 * - Can only index 1 merkletree
 * - Can only index up to 1000 transactions
 *
 * For advanced testing use photon: https://github.com/helius-labs/photon
 */

export class TestRpc extends Rpc {
    merkleTreeAddress: PublicKey;
    nullifierQueueAddress: PublicKey;
    lightWasm: LightWasm;
    depth: number;
    log = false;

    /**
     * Instantiate a mock RPC simulating the compression rpc interface.
     *
     * @param endpoint              endpoint to the solana cluster (use for
     *                              localnet only)
     * @param hasher                light wasm hasher instance
     * @param testRpcConfig         Config for the mock rpc
     * @param proverEndpoint        Optional endpoint to the prover server.
     *                              defaults to endpoint
     * @param connectionConfig      Optional connection config
     */
    constructor(
        endpoint: string,
        hasher: LightWasm,
        compressionApiEndpoint: string,
        proverEndpoint: string,
        connectionConfig?: ConnectionConfig,
        testRpcConfig?: TestRpcConfig,
    ) {
        super(
            endpoint,
            compressionApiEndpoint,
            proverEndpoint,
            connectionConfig,
        );

        const { merkleTreeAddress, nullifierQueueAddress, depth, log } =
            testRpcConfig ?? {};

        const { merkleTree, nullifierQueue, merkleTreeHeight } =
            defaultTestStateTreeAccounts();

        this.lightWasm = hasher;
        this.merkleTreeAddress = merkleTreeAddress ?? merkleTree;
        this.nullifierQueueAddress = nullifierQueueAddress ?? nullifierQueue;
        this.depth = depth ?? merkleTreeHeight;
        this.log = log ?? false;
    }

    /**
     * @internal
     * Returns newest first
     * */
    async getParsedEvents(): Promise<PublicTransactionEvent[]> {
        const { noopProgram, accountCompressionProgram } =
            defaultStaticAccountsStruct();

        /// Get raw transactions
        const signatures = (
            await this.getConfirmedSignaturesForAddress2(
                accountCompressionProgram,
                undefined,
                'confirmed',
            )
        ).map(s => s.signature);
        const txs = await this.getParsedTransactions(signatures, {
            maxSupportedTransactionVersion: 0,
            commitment: 'confirmed',
        });

        /// Filter by NOOP program
        const transactionEvents = txs.filter(
            (tx: ParsedTransactionWithMeta | null) => {
                if (!tx) {
                    return false;
                }
                const accountKeys = tx.transaction.message.accountKeys;

                const hasSplNoopAddress = accountKeys.some(
                    (item: ParsedMessageAccount) => {
                        const itemStr =
                            typeof item === 'string'
                                ? item
                                : item.pubkey.toBase58();
                        return itemStr === noopProgram.toBase58();
                    },
                );

                return hasSplNoopAddress;
            },
        );

        /// Parse events
        const parsedEvents = parseEvents(
            transactionEvents,
            parsePublicTransactionEventWithIdl,
        );

        return parsedEvents;
    }

    /** Retrieve validity proof for compressed accounts */
    async getValidityProof(
        compressedAccountHashes: BN254[],
    ): Promise<CompressedProofWithContext> {
        /// rebuild tree
        const events: PublicTransactionEvent[] =
            await this.getParsedEvents().then(events => events.reverse());

        const allLeaves: number[][] = [];
        const allLeafIndices: number[] = [];
        for (const event of events) {
            for (
                let index = 0;
                index < event.outputCompressedAccounts.length;
                index++
            ) {
                const hash = event.outputCompressedAccountHashes[index];

                allLeaves.push(hash);
                allLeafIndices.push(event.outputLeafIndices[index]);
            }
        }

        const tree = new MerkleTree(
            this.depth,
            this.lightWasm,
            allLeaves.map(leaf => bn(leaf).toString()),
        );

        /// create merkle proofs
        const leafIndices = compressedAccountHashes.map(compressedAccountHash =>
            tree.indexOf(compressedAccountHash.toString()),
        );

        const hexPathElementsAll = leafIndices.map(leafIndex => {
            const pathElements: string[] = tree.path(leafIndex).pathElements;

            const hexPathElements = pathElements.map(value => toHex(bn(value)));

            return hexPathElements;
        });

        const roots = new Array(compressedAccountHashes.length).fill(
            toHex(bn(tree.root())),
        );

        const inputs = {
            roots,
            inPathIndices: leafIndices,
            inPathElements: hexPathElementsAll,
            leaves: compressedAccountHashes.map(compressedAccountHash =>
                toHex(compressedAccountHash),
            ),
        };

        /// Validate
        compressedAccountHashes.forEach((compressedAccountHash, index) => {
            const leafIndex = leafIndices[index];
            const computedHash = tree.elements()[leafIndex].toString();
            if (computedHash !== compressedAccountHash.toString()) {
                throw new Error(
                    `Mismatch at index ${index}: expected ${compressedAccountHash.toString()}, got ${computedHash}`,
                );
            }
        });

        const inputsData = JSON.stringify(inputs);

        let logMsg: string = '';
        if (this.log) {
            logMsg = `Proof generation for depth:${this.depth} n:${compressedAccountHashes.length}`;
            console.time(logMsg);
        }
        // TODO: pass url into rpc constructor
        const SERVER_URL = 'http://localhost:3001';
        const INCLUSION_PROOF_URL = `${SERVER_URL}/inclusion`;

        const response = await fetch(INCLUSION_PROOF_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: inputsData,
        });
        if (!response.ok) {
            throw new Error(`Error fetching proof: ${response.statusText}`);
        }
        // TOOD: add type coercion
        const data: any = await response.json();
        const parsed = proofFromJsonStruct(data);
        const compressedProof = negateAndCompressProof(parsed);

        if (this.log) console.timeEnd(logMsg);

        // TODO: in prover server, fix property names
        const value: CompressedProofWithContext = {
            compressedProof,
            roots: roots,
            // TODO: temporary
            rootIndices: leafIndices.map(_ => allLeafIndices.length),
            leafIndices,
            leaves: compressedAccountHashes,
            merkleTrees: leafIndices.map(_ => this.merkleTreeAddress),
            nullifierQueues: leafIndices.map(_ => this.nullifierQueueAddress),
        };
        return value;
    }
}
