import { ccc, Script, SignerCkbPrivateKey } from "@ckb-ccc/core";
import { useCallback, useState } from "react";
import { InputOnChangeData } from "semantic-ui-react";
import { cccClient } from "./ccc-client";

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
    window.crypto.getRandomValues(result);
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
