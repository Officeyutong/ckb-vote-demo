import { Address, ccc, Script, ScriptLike, SignerCkbPrivateKey } from "@ckb-ccc/core";
import { useCallback, useState } from "react";
import { InputOnChangeData } from "semantic-ui-react";
import { cccClient } from "./ccc-client";
import * as bigintConversion from 'bigint-conversion'

export type onChangeType = ((event: React.ChangeEvent<HTMLInputElement>, data: InputOnChangeData) => void);

export const useInputValue: (text?: string) => { value: string; onChange: onChangeType } = (text: string = "") => {
    const [value, setValue] = useState(text);
    let onChange: onChangeType = useCallback((_, d) => {
        setValue(d.value);
    }, []);
    return { value, onChange };
};
export function randCandidateId(): Uint8Array {
    const result = new Uint8Array(4);
    globalThis.crypto.getRandomValues(result);
    return result;
}
export function uint8ArrToHex(s: Uint8Array): string {
    return Array.from(s).map(x => x.toString(16).padStart(2, "0")).join("")
}
export function convertJWKNumber(input: string): bigint {
    return BigInt("0x00" + Buffer.from(input, "base64").toString("hex"))
}
export type Account = {
    lockScript: Script;
    address: string;
    pubKey: string;
    signer: SignerCkbPrivateKey;
};

export const generateAccountFromPrivateKey = async (
    privKey: string
): Promise<Account> => {
    const signer = new ccc.SignerCkbPrivateKey(cccClient, privKey);
    const lock = await signer.getAddressObjSecp256k1();
    return {
        lockScript: lock.script,
        address: lock.toString(),
        pubKey: signer.publicKey,
        signer
    };
};

export interface CandidateEntry {
    id: Uint8Array;
    description: string;
}

export interface RSAPubKey {
    e: bigint;
    n: bigint;
}
export function encodeCandidate(data: CandidateEntry[]): ArrayBuffer {
    const buf = Buffer.alloc(2 + data.length * 104);
    let idx = 0;
    idx = buf.writeUInt16LE(data.length); // Number of candidate
    for (const item of data) {
        buf.set(item.id, idx);
        idx += 4;
        const writtenLen = buf.write(item.description, idx, 99, "utf8");
        idx += writtenLen;
        for (let i = 1; i <= 100 - writtenLen; i++) {
            buf.writeInt8(0, idx); idx++;
        };
    }
    return buf.buffer;
}
export function decodeCandidate(buf: Buffer): CandidateEntry[] {
    let idx = 0;
    const n = buf.readUInt16LE(); idx += 2;
    const result: CandidateEntry[] = [];
    for (let i = 0; i < n; i++) {
        const id = new Uint8Array(buf.subarray(idx, idx + 4));
        idx += 4;
        let lastZero = idx + 100 - 1;
        while (buf.at(lastZero) == 0 && lastZero > idx) lastZero--;
        const description = buf.toString("utf-8", idx, lastZero + 1);
        idx += 100;
        result.push({
            id, description
        })
    }

    return result;
}
export function encodePubKeyArray(keys: RSAPubKey[]): ArrayBuffer {
    const buf = Buffer.alloc(2 + keys.length * (256 + 4));
    let idx = 0;
    idx = buf.writeUint16LE(keys.length);
    for (const item of keys) {
        const nBuf = bigintConversion.bigintToBuf(item.n, true) as ArrayBuffer;
        // bigintConversion gives us big endian, so reverse it
        if (nBuf.byteLength > 256) throw new Error("Bad modulus");
        buf.set(new Uint8Array(nBuf).reverse(), idx);
        idx += 256;
    }
    for (const item of keys) {
        const eBuf = bigintConversion.bigintToBuf(item.e, true) as ArrayBuffer;
        if (eBuf.byteLength > 4) throw new Error("Bad public exponent");
        buf.set(new Uint8Array(eBuf).reverse(), idx);
        idx += 4;
    }
    return buf.buffer;
}
export function decodePubKeyArray(buf: Buffer): RSAPubKey[] {
    const result: Partial<RSAPubKey>[] = [];
    let idx = 0;
    const n = buf.readUint16LE(); idx += 2;
    for (let i = 0; i < n; i++) {
        const n = bigintConversion.bufToBigint(buf.subarray(idx, idx + 256).reverse() /* We are in little endian*/);
        idx += 256;

        result.push({ n });

    }
    for (let i = 0; i < n; i++) {
        const e = bigintConversion.bufToBigint(buf.subarray(idx, idx + 4).reverse() /* We are in little endian*/);
        idx += 4;
        result[i].e = e;
    }
    return result as RSAPubKey[];
}
export interface PubkeyIndexEntry {
    index: number;
    txHash: Uint8Array;
}

export function encodePubkeyIndexCell(entries: PubkeyIndexEntry[]): ArrayBuffer {
    const buf = Buffer.alloc(2 + entries.length * (32 + 4));
    let idx = 0;
    idx = buf.writeUint16LE(entries.length);
    for (const item of entries) {
        buf.set(item.txHash, idx);
        idx += 32;
    }
    for (const item of entries) {
        idx = buf.writeUint32LE(item.index, idx);
    }

    return buf.buffer;
}

export function decodePubkeyIndexCell(buf: Buffer): PubkeyIndexEntry[] {
    const result: Partial<PubkeyIndexEntry>[] = [];
    let idx = 0;
    const n = buf.readUint16LE(); idx += 2;
    for (let i = 0; i < n; i++) {
        const txHash = new Uint8Array(buf.subarray(idx, idx + 32));
        idx += 32;
        result.push({ txHash });
    }
    for (let i = 0; i < n; i++) {
        const index = buf.readUint32LE(idx); idx += 4;
        result[i].index = index;
    }

    return result as PubkeyIndexEntry[];
}

export interface PreparedTx { sendTx: () => Promise<string>; tx: ccc.Transaction };
export async function publishBytesAsCell(bytes: ArrayBuffer, lockScript: ScriptLike, signer: SignerCkbPrivateKey, dataName: string): Promise<PreparedTx> {
    const tx = ccc.Transaction.from({
        outputs: [{ lock: lockScript }],
        outputsData: [bytes]
    });


    // const balanceDiff =
    //     (await tx.getInputsCapacity(cccClient)) - tx.getOutputsCapacity();
    // if (balanceDiff < 0) {
    //     throw new Error(`Insufficient balance: missing ${Math.abs(parseFloat(balanceDiff.toString()) / 100000000)} CKB for publishing ${dataName} data`)
    // }
    return {
        sendTx: async () => {
            await tx.completeFeeBy(signer, 1000);
            await tx.completeInputsAll(signer);
            return await signer.sendTransaction(tx);
        },
        tx
    };
}

export interface AccountData {
    account: Account;
    address: Address;
    balance: bigint;
}
