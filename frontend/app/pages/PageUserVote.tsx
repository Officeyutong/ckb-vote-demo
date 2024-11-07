import { Button, Dimmer, Form, Input, Loader, Message, Modal, Progress, Table, TextArea } from "semantic-ui-react";
import { AccountData, CandidateEntry, CHUNK_SIZE, convertJWKNumber, decodeCandidate, decodePubKeyArray, decodeUint32LE, encodeBigIntArray, encodeUint32LE, PubkeyIndexEntry, RSAPubKey, uint8ArrToHex, useInputValue } from "../utils";
import { useRef, useState } from "react";
import { cccClient } from "../ccc-client";
import { ccc } from "@ckb-ccc/core";
import { bigintToBuf, bufToHex, hexToBuf } from "bigint-conversion";
import _ from "lodash";
import { create_merkle_tree_proof_rsa, create_ring_signature_rsa_wasm } from "signature-tools-wasm";
import offCKBConfig from "@/offckb.config";
import { useSigner } from "@ckb-ccc/connector-react";
enum Stage {
    INIT = 0,
    CANDIDATE_LOADED = 1,
    VOTED = 2
}

interface StageInit {
    stage: Stage.INIT;
}

interface StageCandidateLoaded {
    stage: Stage.CANDIDATE_LOADED;
    candidate: CandidateEntry[];
    merkleRootHash: string;
    merkleLeafCount: number;
    accountData: AccountData;
    pubKeys: RSAPubKey[];
}

interface StageVoted extends Omit<StageCandidateLoaded, "stage"> {
    txHash: string;
    stage: Stage.VOTED;
}


const extractPQEDFromPrivateKey = (key: any): { n: bigint; p: bigint; q: bigint; e: bigint; d: bigint } => {

    return ({
        n: convertJWKNumber(key.n as string),
        p: convertJWKNumber(key.p as string),
        q: convertJWKNumber(key.q as string),
        e: convertJWKNumber(key.e as string),
        d: convertJWKNumber(key.d as string),
    })
};

const TEST_PRIVATE_KEY = `{"kty":"RSA","n":"yTEpLlTR5F7jCvWC6_ac8yFnJKZcpzSwfjsQwNQTIA79n_FiiCbapRrOBmm98T66TjvuOnlIiZAScwRhBk3Puy0gcn9WwLwtnw3GhEt0oNY0S4jFH7O-7YMs2DyJ0dpMqmjjTQta3btBu7RdWGBxOUY9K2dwJrzSdtc41bTOXRxa9L3R8fc0mG7F_vgzEIV8zUdXniYxtBlPO-ASB8BUXrDR3ZfmfblwJxyipmYdm-7CZhumsLcgbAlD9n0zdEShBd5H_hMfIM6NH-8Mohxue6-tEjN3MK_l60q9gMB24j31tsAhTNnBJaK7hlJuxXyfkizu9xT5bpXVcm7g1dImaQ","e":"AQAB","d":"uc_Ud7zQiLj1uZZbjvAZrhaIevnGkoqAAmUsqNp0u2P86231EUfJITkrVBLu4NKNIFoLQCfpTVspHt7JeRf-JaGc2QIwLhrdi4seb-p8UVrju2sam5fXWuaOUTtAEfcqXSw32V0GU8hxAhmnKEsR5tKvBdonYy96tVU6YWz2NlipcMJEZMbdLPQ0tblJFJHdOfCUYIWsrxT3s93R_ToivvHrVUvBz-Pr1FWVI01MQlkBGH6g6V0h_vLGDV6KZi_m9z5UgPiie8XgZjGdUhG8kVLW_6dsGfdpI0sG5JNNy9QyzHK7ui5DyCSAXsRMsZSKzFCTMj7xgpsYXmwiJy8ubQ","p":"3N0mcJfz87J6Wal4DHwtjMHthKF6vsCrHQzDqYtx1-Zo7q65M640DI_6EN_Vh15w0AJILMuS5k4bELluJ-pctIYx63AEeQoD5HUs6R3RQC3XNPi8-aKqbZirC00mSNAJG9k92SrWtGzgrZ5MmelqGV7wZb1lcFcbi17EDmaJWsc","q":"6TLcOkvKv1LTPnk_nQLDhUIg0CtxmMjzXhZNebMS9t4VHXkvtuTDR954-fqPhdxcKNnw1N4ojE33UJP8S-4VxFST1eyCnbIpU9GBQXnMzNn9Kb7dZDOO66ENEhUJ-AEv2EjwzXOr1lL8djfBOyJWGhK4-7Ku4YdSC60za5jMxU8","dp":"jFDjrvyau-RT3srPvf7WYWqDH5QHi1CUZWxKklhJB0UWvSy79J1j6-c8k6Pg4JObUEti1zKuLSrJ_yIPXcSDCR2IcW9FKDC4sFfRJHkRC5kT9E9in6Y8aExpvlBRVkj0wICPznxs00uooiTDvbSQ93VdfQWKgIiWs0CNhiiWctk","dq":"iUc7hcXgUMi9OmW-IPvjharsDh_E-6AwRA71BNN6MoGCBJu2jwAURVad-OqbWr3iMto5f9ZYIGA1WuYC-9_oSG9Rp_lW2uZqlcEbSiQdf-pDsjN9uOLxG5zvSNnByJFKTRSDTS7u1Xh8zkr8IYeREEA9TU5ezL0Qe3c2cfy9btk","qi":"A_2U4fZkQwJZZiSpKU6mheY0FKCW_-tqmfYsxhBr9_raVwCbskjysVX_rGtA5jZvXgaOTwt5JzFR8IGgHmBSQda0SI8IKvbEkKz31zcabDCdoTo8S-Vu60YiRZweAU7DKChYyRr073Vjid8y2IgOzF-XAJ2gpL-zyrlDMQiHSE4"}`;

const PageUserVote: React.FC<{}> = () => {
    const [stage, setStage] = useState<StageInit | StageCandidateLoaded | StageVoted>({ stage: Stage.INIT });

    const [doneCount, setDoneCount] = useState(0);
    const [totalCount, setTotalCount] = useState(1);
    const [progressText, setProgressText] = useState<string | null>(null);

    const candidateHash = useInputValue("0x16d71077a3ee88bed50cac3ee5385df77f7c560f58d803bb3c1d939c793aa985");
    const merkleRootHash = useInputValue("0x4cac2ca336c5057934a28a9e45b9bbc3907c8b720a356d29c2e56666af79706d");
    const [signPrivateKey, setSignPrivateKey] = useState(TEST_PRIVATE_KEY);

    const [loading, setLoading] = useState(false);
    const [selectedCandidate, setSelectedCandidate] = useState<CandidateEntry | null>(null);

    const uploadRef = useRef<HTMLInputElement>(null);

    const signer = useSigner();
    console.log(stage);
    const doLoadCandidateAndAccount = async () => {
        if (!signer) {
            alert("Bad signer");
            return;
        }
        try {
            setLoading(true);
            setDoneCount(0);
            setProgressText("Fetching base data..");
            setTotalCount(3);
            const [candidateTx, addressObjs, merkleRootTx] = await Promise.all([
                cccClient.getTransaction(candidateHash.value),
                signer.getAddressObjs(),
                cccClient.getTransaction(merkleRootHash.value),

            ]);
            setDoneCount(1);
            if (!candidateTx) {
                alert("Invalid candidate cell tx hash");
                return;
            }
            if (!merkleRootTx) {
                alert("Invalid merkle root cell tx hash");
                return;
            }
            setProgressText("Fetching balance..");
            const balance = await signer.getBalance();
            setDoneCount(2);

            setProgressText("Loading public keys(merkle tree leaves)..");
            if (!uploadRef.current || !uploadRef.current.files || uploadRef.current.files.length !== 1) {
                alert("Please select exact one file");
                return;
            }
            const file = uploadRef.current.files[0];
            const bytes = await file.arrayBuffer();
            const pubKeys = decodePubKeyArray(Buffer.from(bytes));

            setDoneCount(3);

            const merkleCellData = hexToBuf(merkleRootTx.transaction.outputsData[0]);
            setStage({
                stage: Stage.CANDIDATE_LOADED,
                candidate: decodeCandidate(Buffer.from(hexToBuf(candidateTx.transaction.outputsData[0], true) as ArrayBuffer)),
                accountData: {
                    addresses: addressObjs, balance, signer
                },
                pubKeys,
                merkleRootHash: bufToHex(merkleCellData.slice(0, 32)),
                merkleLeafCount: decodeUint32LE(new Uint8Array(merkleCellData.slice(32, 36)))

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
            setDoneCount(0);
            setTotalCount(4);
            setProgressText("Looking for belonging block..");
            const privateKey = extractPQEDFromPrivateKey(JSON.parse(signPrivateKey));
            let signerIndex: number | undefined;
            for (let i = 0; i < stage.pubKeys.length; i++) {
                const currKey = stage.pubKeys[i];
                if (currKey.e === privateKey.e && currKey.n === privateKey.n) {
                    signerIndex = i; break;
                }
            }
            if (signerIndex === undefined) {
                alert("Unable to find belong block, please ensure you have uploaded the correct merkle tree leaves and your private key is correct");
                return;
            }
            console.log("signer index", signerIndex);
            setDoneCount(1);
            setProgressText("Creating signature..");
            const signerBlock = Math.floor(signerIndex / CHUNK_SIZE);
            const signerBlockIdx = signerIndex % CHUNK_SIZE;
            const blockKeys = stage.pubKeys.slice(signerBlock * CHUNK_SIZE, Math.min((signerBlock + 1) * CHUNK_SIZE, stage.pubKeys.length));


            const signature = create_ring_signature_rsa_wasm(
                blockKeys.length,
                encodeBigIntArray(blockKeys.map(s => s.e), 4),
                encodeBigIntArray(blockKeys.map(s => s.n), 256),
                encodeBigIntArray([privateKey.p], 256),
                encodeBigIntArray([privateKey.q], 256),
                encodeBigIntArray([privateKey.d], 256),
                signerBlockIdx,
                selectedCandidate.id,
            );
            console.log(signature);
            setDoneCount(2);


            setProgressText("Creating merkle proof..");

            const proof = create_merkle_tree_proof_rsa(
                stage.pubKeys.length,
                CHUNK_SIZE,
                encodeBigIntArray(stage.pubKeys.map(s => s.n), 256),
                encodeBigIntArray(stage.pubKeys.map(s => s.e), 4),
                signerBlock);
            console.log(proof);
            setDoneCount(3);

            setProgressText("Creating transaction..");
            const script = offCKBConfig.myScripts["ring-signature-verify"]!;
            const tx = ccc.Transaction.from({
                cellDeps: [
                    ccc.CellDep.from({ outPoint: { txHash: candidateHash.value, index: 0 }, depType: 0 }),
                    ccc.CellDep.from({ outPoint: { txHash: merkleRootHash.value, index: 0 }, depType: 0 }),
                    script.cellDeps[0].cellDep,
                ],
                outputs: [
                    {
                        lock: stage.accountData.addresses[0].script,
                        type: new ccc.Script(
                            script.codeHash,
                            script.hashType,
                            "0x00"
                        )
                    }
                ],
                outputsData: [
                    new Uint8Array([
                        ...selectedCandidate.id,
                        ...signature.i,
                    ])
                ],

            });

            await tx.completeFeeBy(stage.accountData.signer, 1000000);
            await tx.completeInputsAll(stage.accountData.signer);
            const rawWitness = tx.getWitnessArgsAt(0);
            console.log("raw witness", rawWitness);
            tx.setWitnessArgsAt(0, new ccc.WitnessArgs(
                rawWitness?.lock,
                rawWitness?.inputType,
                bufToHex(
                    new Uint8Array([
                        ...signature.c,
                        ...encodeUint32LE(blockKeys.length),
                        ...signature.r_arr,
                        ...encodeBigIntArray(blockKeys.map(s => s.n), 256),
                        ...encodeBigIntArray(blockKeys.map(s => s.e), 4),
                        ...encodeUint32LE(signerBlock),
                        ...encodeUint32LE(proof.proof.length),
                        ...proof.proof
                    ]),
                    true
                ) as `0x${string}`))
            const newTx = await stage.accountData.signer.signTransaction(tx);
            console.log(newTx);
            console.log(newTx.hash());
            const txHash = await cccClient.sendTransaction(newTx);
            setStage({
                ...stage,
                stage: Stage.VOTED,
                txHash
            })
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
                To vote, you need to provideyour private key corresponding to the public key which was sended to administrator, and the candidate you want to vote. Note that don&apos;t vote twice, or only the first vote will be considered valid
            </Message.Content>
        </Message>
        <Form>
            <Form.Field>
                <label>Candidate cell hash</label>
                <Input disabled={stage.stage !== Stage.INIT} {...candidateHash}></Input>
            </Form.Field>
            <Form.Field>
                <label>Merkle root cell hash</label>
                <Input disabled={stage.stage !== Stage.INIT} {...merkleRootHash}></Input>
            </Form.Field>
            <Form.Field>
                <label>Merkle tree leaves data</label>
                <input disabled={stage.stage !== Stage.INIT} type="file" ref={uploadRef}></input>
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
                    <label>Merkle tree root hash</label>
                    <p>{stage.merkleRootHash}</p>
                </Form.Field>
                <Form.Field>
                    <label>Merkle tree leaf count</label>
                    <p>{stage.merkleLeafCount}</p>
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

                {stage.stage === Stage.CANDIDATE_LOADED && <Form.Button onClick={doVote} color="green">
                    Vote
                </Form.Button>}
            </>}
            {stage.stage === Stage.VOTED && <Message info>
                <Message.Header>Successfully voted</Message.Header>
                <Message.Content>
                    Your transaction hash: {stage.txHash}
                </Message.Content>
            </Message>}
        </Form>
    </>
};

export default PageUserVote;
