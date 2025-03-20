export declare const splitSecret: (secret: Uint8Array, threshold: number, shares: number) => Promise<Array<Uint8Array>>;
export declare const combineSecret: (shares: Array<Uint8Array>) => Promise<Uint8Array>;
