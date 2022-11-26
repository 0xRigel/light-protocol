export * from './verifierOne'
export * from './verifierZero'
// export * from './verifierTwo'
import { Program } from "@project-serum/anchor";
import { Transaction } from "../transaction";

export interface PublicInputs {
    root: Array<Number>,
    publicAmount: Array<Number>,
    extDataHash: Array<Number>,
    feeAmount: Array<Number>,
    mintPubkey: Array<Number>,
    nullifiers: Array<Uint8Array>,
    leaves: Array<Array<Number>>,

}

export interface Verifier {
    verifierProgram: Program<any>;
    wtnsGenPath: String;
    zkeyPath: String;
    calculateWtns: NodeRequire;
    sendTransaction(insert: Boolean): Promise<any>;
    parsePublicInputsFromArray(transaction: Transaction): PublicInputs;
  }