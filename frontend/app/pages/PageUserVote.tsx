import { Button, Dimmer, Form, Input, Loader, Message, Modal, Progress, Table, TextArea } from "semantic-ui-react";
import { AccountData, CandidateEntry, convertJWKNumber, decodeCandidate, decodePubKeyArray, decodePubkeyIndexCell, PubkeyIndexEntry, RSAPubKey, uint8ArrToHex, useInputValue } from "../utils";
import { useState } from "react";
import { cccClient } from "../ccc-client";
import { ccc } from "@ckb-ccc/core";
import { bigintToBuf, bufToHex, hexToBuf } from "bigint-conversion";
import _ from "lodash";
import __wbg_init, { create_ring_signature_wasm } from "signature-tools-wasm";
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

interface PubKeyBlock { index: PubkeyIndexEntry; keys: RSAPubKey[]; };

interface StageCandidateLoaded {
    stage: Stage.CANDIDATE_LOADED;
    candidate: CandidateEntry[];
    accountData: AccountData;
    pubKeyIndex: PubkeyIndexEntry[];
    pubKeys: PubKeyBlock[];
}

interface StageVoted extends Omit<StageCandidateLoaded, "stage"> {
    txHash: string;
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
    return result;
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
const PageUserVote: React.FC<{}> = () => {
    const [stage, setStage] = useState<StageInit | StageCandidateLoaded | StageVoted>({ stage: Stage.INIT });

    const [doneCount, setDoneCount] = useState(0);
    const [totalCount, setTotalCount] = useState(1);
    const [progressText, setProgressText] = useState<string | null>(null);

    const candidateHash = useInputValue("");
    const publicKeyIndexCell = useInputValue("");
    const [signPrivateKey, setSignPrivateKey] = useState("")
    const [loading, setLoading] = useState(false);
    const [selectedCandidate, setSelectedCandidate] = useState<CandidateEntry | null>(null);
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
            const [candidateTx, addressObjs, pubkeyIndexTx] = await Promise.all([
                cccClient.getTransaction(candidateHash.value),
                signer.getAddressObjs(),
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
            const balance = await signer.getBalance();

            setStage({
                stage: Stage.CANDIDATE_LOADED,
                candidate: decodeCandidate(Buffer.from(hexToBuf(candidateTx.transaction.outputsData[0], true) as ArrayBuffer)),
                accountData: {
                    addresses: addressObjs, balance, signer
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
            const signature = create_ring_signature_wasm(
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
                        1, // R[] and I are in witness
                        ...selectedCandidate.id,
                        ...signature.i])
                ],

            });

            await tx.completeFeeBy(stage.accountData.signer, 1000000);
            await tx.completeInputsAll(stage.accountData.signer);
            const rawWitness = tx.getWitnessArgsAt(0);
            console.log("raw witness", rawWitness);
            tx.setWitnessArgsAt(0, new ccc.WitnessArgs(rawWitness?.lock, rawWitness?.inputType, bufToHex(new Uint8Array([...signature.c, ...signature.r_arr]), true) as `0x${string}`))
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
                To vote, you need to provide an account with enough balance, private key corresponding to the public key which was sended to administrator, and the candidate you want to vote. Note that don&apos;t vote twice, or only the first vote will be considered valid
            </Message.Content>
        </Message>
        <Form>
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
