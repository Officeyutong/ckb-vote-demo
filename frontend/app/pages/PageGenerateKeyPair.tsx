import { useState } from "react";
import { Button, Dimmer, Loader } from "semantic-ui-react";
import * as asn1js from "asn1js";
import { PrivateKeyInfo, RSAPrivateKey } from "pkijs";


const extractPQEDFromPrivateKey = async (privateKey: CryptoKey): Promise<{ p: BigInt, q: BigInt, e: BigInt; d: BigInt }> => {
    const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);

    const asn1 = asn1js.fromBER(pkcs8);
    if (asn1.offset === -1) {
        throw new Error("Error parsing PKCS8");
    }
    const privateKeyInfo = new PrivateKeyInfo({ schema: asn1.result });
    console.log(privateKeyInfo);
    const rsaPrivateKey = new RSAPrivateKey({ schema: privateKeyInfo.privateKey.valueBlock.valueHexView });
    return { e: rsaPrivateKey.publicExponent.toBigInt(), d: rsaPrivateKey.privateExponent.toBigInt(), p: rsaPrivateKey.prime1.toBigInt(), q: rsaPrivateKey.prime2.toBigInt(), };
};

const PageGenerateKeyPair: React.FC<{}> = () => {
    const [loading, setLoading] = useState(false);

    const doGenerate = async () => {
        try {
            setLoading(true);
            const key = await window.crypto.subtle.generateKey({
                name: "RSA-OAEP", modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
                true, ["decrypt", "encrypt"]);
            console.log("started...");
            console.log(await extractPQEDFromPrivateKey(key.privateKey));
        } catch (e) {
            alert(e);
            throw e;
        } finally {
            setLoading(false);
        }

    };
    return <>
        {loading && <Dimmer page active><Loader></Loader></Dimmer>}
        <Button color="green" onClick={doGenerate}>Generate</Button>
    </>;

}


export default PageGenerateKeyPair;
