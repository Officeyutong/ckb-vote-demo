import { Button, Dimmer, Form, Input, Loader, Message, Modal, Progress, Table, TextArea } from "semantic-ui-react";
import { AccountData, CandidateEntry, convertJWKNumber, decodeCandidate, decodePubKeyArray, decodePubkeyIndexCell, generateAccountFromPrivateKey, PubkeyIndexEntry, RSAPubKey, uint8ArrToHex, useInputValue } from "../utils";
import { useState } from "react";
import { cccClient } from "../ccc-client";
import { ccc } from "@ckb-ccc/core";
import { bigintToBuf, bufToHex, hexToBuf } from "bigint-conversion";
import _ from "lodash";
import __wbg_init, { create_signature_wasm } from "rsa_ring_sign_linkable_wasm";
import offCKBConfig from "@/offckb.config";
enum Stage {
    INIT = 0,
    CANDIDATE_LOADED = 1,
    VOTED = 2
}

interface StageInit {
    stage: Stage.INIT;
}

interface PubKeyBlock { index: PubkeyIndexEntry; keys: RSAPubKey[]; };

interface StageCandidateLoaded {
    stage: Stage.CANDIDATE_LOADED;
    candidate: CandidateEntry[];
    accountData: AccountData;
    pubKeyIndex: PubkeyIndexEntry[];
    pubKeys: PubKeyBlock[];
}

interface StageVoted extends Omit<StageCandidateLoaded, "stage"> {
    stage: Stage.VOTED;
}

function encodeBigIntArray(arr: bigint[], entrySize: number): Uint8Array {
    const buf = Buffer.alloc(arr.length * entrySize);
    let idx = 0;
    for (const item of arr) {
        const nBuf = bigintToBuf(item, true) as ArrayBuffer;
        buf.set(new Uint8Array(nBuf).reverse(), idx);
        idx += entrySize;
    }
    const result = new Uint8Array(buf.buffer);
    // console.log(arr, "->", result);
    return result;
}

const EXAMPLE_PRIVATE_KEY = `{"kty":"RSA","n":"yTEpLlTR5F7jCvWC6_ac8yFnJKZcpzSwfjsQwNQTIA79n_FiiCbapRrOBmm98T66TjvuOnlIiZAScwRhBk3Puy0gcn9WwLwtnw3GhEt0oNY0S4jFH7O-7YMs2DyJ0dpMqmjjTQta3btBu7RdWGBxOUY9K2dwJrzSdtc41bTOXRxa9L3R8fc0mG7F_vgzEIV8zUdXniYxtBlPO-ASB8BUXrDR3ZfmfblwJxyipmYdm-7CZhumsLcgbAlD9n0zdEShBd5H_hMfIM6NH-8Mohxue6-tEjN3MK_l60q9gMB24j31tsAhTNnBJaK7hlJuxXyfkizu9xT5bpXVcm7g1dImaQ","e":"AQAB","d":"uc_Ud7zQiLj1uZZbjvAZrhaIevnGkoqAAmUsqNp0u2P86231EUfJITkrVBLu4NKNIFoLQCfpTVspHt7JeRf-JaGc2QIwLhrdi4seb-p8UVrju2sam5fXWuaOUTtAEfcqXSw32V0GU8hxAhmnKEsR5tKvBdonYy96tVU6YWz2NlipcMJEZMbdLPQ0tblJFJHdOfCUYIWsrxT3s93R_ToivvHrVUvBz-Pr1FWVI01MQlkBGH6g6V0h_vLGDV6KZi_m9z5UgPiie8XgZjGdUhG8kVLW_6dsGfdpI0sG5JNNy9QyzHK7ui5DyCSAXsRMsZSKzFCTMj7xgpsYXmwiJy8ubQ","p":"3N0mcJfz87J6Wal4DHwtjMHthKF6vsCrHQzDqYtx1-Zo7q65M640DI_6EN_Vh15w0AJILMuS5k4bELluJ-pctIYx63AEeQoD5HUs6R3RQC3XNPi8-aKqbZirC00mSNAJG9k92SrWtGzgrZ5MmelqGV7wZb1lcFcbi17EDmaJWsc","q":"6TLcOkvKv1LTPnk_nQLDhUIg0CtxmMjzXhZNebMS9t4VHXkvtuTDR954-fqPhdxcKNnw1N4ojE33UJP8S-4VxFST1eyCnbIpU9GBQXnMzNn9Kb7dZDOO66ENEhUJ-AEv2EjwzXOr1lL8djfBOyJWGhK4-7Ku4YdSC60za5jMxU8","dp":"jFDjrvyau-RT3srPvf7WYWqDH5QHi1CUZWxKklhJB0UWvSy79J1j6-c8k6Pg4JObUEti1zKuLSrJ_yIPXcSDCR2IcW9FKDC4sFfRJHkRC5kT9E9in6Y8aExpvlBRVkj0wICPznxs00uooiTDvbSQ93VdfQWKgIiWs0CNhiiWctk","dq":"iUc7hcXgUMi9OmW-IPvjharsDh_E-6AwRA71BNN6MoGCBJu2jwAURVad-OqbWr3iMto5f9ZYIGA1WuYC-9_oSG9Rp_lW2uZqlcEbSiQdf-pDsjN9uOLxG5zvSNnByJFKTRSDTS7u1Xh8zkr8IYeREEA9TU5ezL0Qe3c2cfy9btk","qi":"A_2U4fZkQwJZZiSpKU6mheY0FKCW_-tqmfYsxhBr9_raVwCbskjysVX_rGtA5jZvXgaOTwt5JzFR8IGgHmBSQda0SI8IKvbEkKz31zcabDCdoTo8S-Vu60YiRZweAU7DKChYyRr073Vjid8y2IgOzF-XAJ2gpL-zyrlDMQiHSE4"}`;
const extractPQEDFromPrivateKey = (key: any): { n: bigint; p: bigint; q: bigint; e: bigint; d: bigint } => {

    return ({
        n: convertJWKNumber(key.n as string),
        p: convertJWKNumber(key.p as string),
        q: convertJWKNumber(key.q as string),
        e: convertJWKNumber(key.e as string),
        d: convertJWKNumber(key.d as string),
    })
};
const PageUserVote: React.FC<{}> = () => {
    const [stage, setStage] = useState<StageInit | StageCandidateLoaded | StageVoted>({ stage: Stage.INIT });

    const [doneCount, setDoneCount] = useState(0);
    const [totalCount, setTotalCount] = useState(1);
    const [progressText, setProgressText] = useState<string | null>(null);

    // A private key from devnet account
    const accountPrivateKey = useInputValue("0xa5808e79c243d8e026a034273ad7a5ccdcb2f982392fd0230442b1734c98a4c2");
    const candidateHash = useInputValue("0x205284fab97f8a408a15b326fa84f0046780ce882ba1c7e5bbdb3602dcba51aa");
    const publicKeyIndexCell = useInputValue("0x79b7f4ba0faa8eca3ab4dd6f3d9060aa82b069add49c3083c14ee47551522f49");
    const [signPrivateKey, setSignPrivateKey] = useState(EXAMPLE_PRIVATE_KEY)
    const [loading, setLoading] = useState(false);
    const [selectedCandidate, setSelectedCandidate] = useState<CandidateEntry | null>(null);
    console.log(stage);
    const doLoadCandidateAndAccount = async () => {
        try {
            setLoading(true);
            setDoneCount(0);
            setProgressText("Fetching base data..");
            setTotalCount(3);
            const [candidateTx, account, pubkeyIndexTx] = await Promise.all([
                cccClient.getTransaction(candidateHash.value),
                generateAccountFromPrivateKey(accountPrivateKey.value),
                cccClient.getTransaction(publicKeyIndexCell.value),

            ]);
            setDoneCount(3);
            if (!candidateTx) {
                alert("Invalid candidate cell tx hash");
                return;
            }
            if (!pubkeyIndexTx) {
                alert("Invalid pubkey index cell tx hash");
                return;
            }
            const pubKeyIndex = decodePubkeyIndexCell(Buffer.from(hexToBuf(pubkeyIndexTx.transaction.outputsData[0], true) as ArrayBuffer))
            console.log(pubKeyIndex);
            setProgressText("Fetching all public keys..");
            setDoneCount(0);
            setTotalCount(Math.ceil(pubKeyIndex.length / 10));
            let pubKeys: { index: PubkeyIndexEntry; keys: RSAPubKey[]; }[] = [];
            for (const chunk of _.chunk(pubKeyIndex, 10)) {
                const keyChunks = await Promise.all(
                    chunk.map(item => Promise.all([
                        cccClient.getTransaction(item.txHash),
                        Promise.resolve(item)
                    ]))
                );
                pubKeys = pubKeys.concat(keyChunks.map(([tx, index]) => {
                    if (!tx) throw new Error(`Invalid tx encountered for index cell hash ${uint8ArrToHex(index.txHash)}:${index.index}`);
                    return ({ keys: decodePubKeyArray(Buffer.from(hexToBuf(tx.transaction.outputsData[index.index], true) as ArrayBuffer)), index });
                }))
                setDoneCount(c => c + 1);
            }
            const [address, balance] = await Promise.all([
                ccc.Address.fromString(account.address, cccClient),
                cccClient.getBalance([account.lockScript])
            ]);


            setStage({
                stage: Stage.CANDIDATE_LOADED,
                candidate: decodeCandidate(Buffer.from(hexToBuf(candidateTx.transaction.outputsData[0], true) as ArrayBuffer)),
                accountData: {
                    account, address, balance
                },
                pubKeyIndex,
                pubKeys
            })
        } catch (e) { console.error(e); alert(e) } finally {
            setLoading(false);
            setProgressText(null);
        }
    }
    const doVote = async () => {
        try {
            if (stage.stage !== Stage.CANDIDATE_LOADED) {
                alert("Bad stage"); return;
            }
            if (selectedCandidate === null) {
                alert("Please select a candidate");
                return;
            }
            setDoneCount(0); setTotalCount(3);
            setProgressText("Looking for belonging block..");
            const privateKey = extractPQEDFromPrivateKey(JSON.parse(signPrivateKey));
            let index: PubKeyBlock | undefined;
            let signerIndex: number | undefined;
            for (const block of stage.pubKeys) {
                for (const [entry, idx] of block.keys.map((val, idx) => [val, idx] as [RSAPubKey, number])) {
                    if (entry.n === privateKey.n && entry.e === privateKey.e) {
                        index = block;
                        signerIndex = idx;
                        break;
                    }
                }
                if (index) break;
            }
            if (!index || signerIndex === undefined) {
                alert("Unable to find belong block, please ensure your public key index cell is correct");
                return;
            }
            console.log("index block", index);
            setDoneCount(1);
            setProgressText("Creating signature..");
            await __wbg_init();
            const signature = create_signature_wasm(
                index.keys.length,
                encodeBigIntArray(index.keys.map(s => s.e), 4),
                encodeBigIntArray(index.keys.map(s => s.n), 256),
                encodeBigIntArray([privateKey.p], 256),
                encodeBigIntArray([privateKey.q], 256),
                encodeBigIntArray([privateKey.d], 256),
                signerIndex,
                selectedCandidate.id,
            );
            console.log(signature);
            setDoneCount(2);

            setProgressText("Creating transaction..");
            const script = offCKBConfig.myScripts["ring-signature-verify"]!;
            const tx = ccc.Transaction.from({
                cellDeps: [
                    ccc.CellDep.from({ outPoint: { txHash: candidateHash.value, index: 0 }, depType: 0 }),
                    ccc.CellDep.from({ outPoint: { txHash: index.index.txHash, index: index.index.index }, depType: 0 }),
                    script.cellDeps[0].cellDep
                    // ccc.CellDep.from({ outPoint: { txHash: candidateHash.value, index: 0 }, depType: 0 }),
                    // ccc.CellDep.from({ outPoint: { txHash: offCKBConfig.myScripts["ring-signature-verify"]!.codeHash, index: 0 }, depType: 0 }),
                ],
                outputs: [
                    {
                        lock: stage.accountData.account.lockScript, type: new ccc.Script(
                            script.codeHash,
                            script.hashType,
                            "0x00"
                        )
                    }
                ],
                outputsData: [
                    new Uint8Array([
                        ...selectedCandidate.id,
                        ...signature.c,
                        ...signature.r_arr,
                        ...signature.i])
                ],

            });

            // tx.
            await tx.completeFeeBy(stage.accountData.account.signer, 1000000);
            await tx.completeInputsAll(stage.accountData.account.signer);
            const newTx = await stage.accountData.account.signer.signTransaction(tx);
            // newTx.setWitnessArgsAt(1, new ccc.WitnessArgs(undefined, undefined, bufToHex(new Uint8Array([...signature.c, ...signature.r_arr]), true) as `0x${string}`))

            console.log(newTx);
            const txHash = await cccClient.sendTransaction(newTx);

            console.log(txHash);
        } catch (e) {
            console.error(e);
            alert(e);
        } finally {
            setProgressText(null);
        }
    };
    return <>
        {progressText !== null && <Modal open size="small">
            <Modal.Header>Progress</Modal.Header>
            <Modal.Content>
                <Progress color="green" percent={Math.floor(100 * doneCount / totalCount)} active label={progressText}></Progress>
            </Modal.Content>
        </Modal>}
        {loading && progressText === null && <Dimmer active page>
            <Loader></Loader>
        </Dimmer>}
        <Message info>
            <Message.Header>To vote</Message.Header>
            <Message.Content>
                To vote, you need to provide an account with enough balance, private key corresponding to the public key which was sended to administrator, and the candidate you want to vote. Note that don&apos;t vote twice, or only the first vote will be considered valid
            </Message.Content>
        </Message>
        <Form>
            <Form.Field>
                <label>Account private key</label>
                <Input disabled={stage.stage !== Stage.INIT} {...accountPrivateKey}></Input>
            </Form.Field>
            <Form.Field>
                <label>Candidate cell hash</label>
                <Input disabled={stage.stage !== Stage.INIT} {...candidateHash}></Input>
            </Form.Field>
            <Form.Field>
                <label>Public key index cell hash</label>
                <Input disabled={stage.stage !== Stage.INIT} {...publicKeyIndexCell}></Input>
            </Form.Field>
            {stage.stage === Stage.INIT && <Form.Button
                onClick={doLoadCandidateAndAccount}
                color="green"
            >
                Load account and candidates
            </Form.Button>}
            {stage.stage === Stage.CANDIDATE_LOADED && <>
                <Form.Field>
                    <label>Private key of signature</label>
                    <TextArea value={signPrivateKey} onChange={(_, d) => setSignPrivateKey(d.value as string)}></TextArea>
                </Form.Field>
                <Form.Field>
                    <label>Candidate</label>
                    <Table>
                        <Table.Header>
                            <Table.Row>
                                <Table.HeaderCell>Candidate ID</Table.HeaderCell>
                                <Table.HeaderCell>Description</Table.HeaderCell>
                                <Table.HeaderCell>Operations</Table.HeaderCell>
                            </Table.Row>
                        </Table.Header>
                        <Table.Body>
                            {stage.candidate.map(item => {
                                const idStr = uint8ArrToHex(item.id);
                                return <Table.Row key={idStr}>
                                    <Table.Cell>{idStr}</Table.Cell>
                                    <Table.Cell>{item.description}</Table.Cell>
                                    <Table.Cell>
                                        {(selectedCandidate && idStr === uint8ArrToHex(selectedCandidate.id)) ? <Button size="small" color="red" disabled>Selected</Button> : <Button size="small" color="green" onClick={() => setSelectedCandidate(item)}>Select</Button>}
                                    </Table.Cell>
                                </Table.Row>;
                            })}
                        </Table.Body>
                    </Table>
                </Form.Field>
                <Form.Button onClick={doVote} color="green">
                    Vote
                </Form.Button>
            </>}
        </Form>
    </>
};

export default PageUserVote;
