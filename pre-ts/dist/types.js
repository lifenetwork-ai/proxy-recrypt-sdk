export class SecretKey {
    constructor(first, second) {
        this.first = first;
        this.second = second;
    }
    toBytes() {
        const firstBytes = this.first.toString(16).padStart(64, "0");
        const secondBytes = this.second.toString(16).padStart(64, "0");
        return new Uint8Array(Buffer.from(firstBytes + secondBytes, "hex"));
    }
    static fromBytes(bytes) {
        const hex = Buffer.from(bytes).toString("hex");
        return new SecretKey(BigInt("0x" + hex.slice(0, 64)), BigInt("0x" + hex.slice(64, 128)));
    }
}
