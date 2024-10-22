import { useState } from "react";
import { Button, Dimmer, Divider, Form, Loader, Message } from "semantic-ui-react";


function convertNumber(input: string): bigint {
    return BigInt("0x00" + Buffer.from(input, "base64").toString("hex"))
}
const extractPQEDFromPrivateKey = async (privateKey: CryptoKey): Promise<{ n: BigInt; p: BigInt; q: BigInt; e: BigInt; d: BigInt }> => {
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);

    return ({
        n: convertNumber(jwk.n!),
        p: convertNumber(jwk.p!),
        q: convertNumber(jwk.q!),
        e: convertNumber(jwk.e!),
        d: convertNumber(jwk.d!),
    })
};

const PageGenerateKeyPair: React.FC<{}> = () => {
    const [loading, setLoading] = useState(false);
    const [pubKey, setPubKey] = useState<string | null>(null);
    const [privateKey, setPrivateKey] = useState<string | null>(null);

    const doGenerate = async () => {
        try {
            setLoading(true);
            const key = await window.crypto.subtle.generateKey({
                name: "RSA-OAEP", modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
                true, ["decrypt", "encrypt"]);
            setPubKey(JSON.stringify(await window.crypto.subtle.exportKey("jwk", key.publicKey)));
            setPrivateKey(JSON.stringify(await window.crypto.subtle.exportKey("jwk", key.privateKey)));

        } catch (e) {
            alert(e);
            console.error(e);
            throw e;
        } finally {
            setLoading(false);
        }

    };
    return <>
        {loading && <Dimmer page active><Loader></Loader></Dimmer>}
        <Button color="green" onClick={doGenerate}>Generate</Button>
        {(pubKey !== null || privateKey !== null) && <>

            <Divider></Divider>
            <Message info success>
                <Message.Header>Generation done</Message.Header>
                <Message.Content>
                    Please keep your private key and send your public key to the administrator
                </Message.Content>
            </Message>
            <Form>
                {privateKey !== null && <Form.TextArea label="Private key" value={privateKey} onChange={() => { }}></Form.TextArea>}
                {pubKey !== null && <Form.TextArea label="Public key" value={pubKey} onChange={() => { }}></Form.TextArea>}

            </Form>
        </>
        }
    </>;

}


export default PageGenerateKeyPair;
