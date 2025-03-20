import { GTElement } from "./bn254";
export declare function generateRandomSymmetricKeyFromGT(keySize?: number): Required<{
    keyGT: GTElement;
    key: Uint8Array;
}>;
export declare function deriveKeyFromGT(gtElement: GTElement, keySize?: number): Uint8Array;
