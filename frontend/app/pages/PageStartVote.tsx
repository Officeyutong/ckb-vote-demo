import { useRef, useState } from "react";
import { Button, Dimmer, Divider, Form, Input, InputOnChangeData, Loader, Message, Modal, Progress, Table, TextArea } from "semantic-ui-react";
import { Address, ccc } from "@ckb-ccc/core";
import { Account, AccountData, CandidateEntry, convertJWKNumber, encodeCandidate, encodePubKeyArray, encodePubkeyIndexCell, generateAccountFromPrivateKey, PreparedTx, publishBytesAsCell, randCandidateId, RSAPubKey, uint8ArrToHex, useInputValue } from "../utils";
import { cccClient } from "../ccc-client";
import _ from "lodash";
import * as bigintConversion from 'bigint-conversion'

const CHUNK_SIZE = 450;


interface VoteTransactions {
    candidate: PreparedTx;
    pubKeys: PreparedTx[];
}

interface VoteCreationResult {
    candidateCellTxHash: string;
    publicKeyCellTxHash: string[];
    publicKeyIndexCellTxHash: string;
}

enum Stage {
    INIT = 1,
    ACCOUNT_LOADED = 2,
    DATA_PREPARED = 3,
    SENDED = 4

}

interface StageInit {
    stage: Stage.INIT;
}

interface StageAccountLoaded {
    stage: Stage.ACCOUNT_LOADED;
    accountData: AccountData;
}
interface StageDataPrepared {
    stage: Stage.DATA_PREPARED;
    accountData: AccountData;
    preparedTx: VoteTransactions;
    prompt: string;
}
interface StageSended {
    stage: Stage.SENDED;
    accountData: AccountData;
    preparedTx: VoteTransactions;
    pubKeyIndexTx: PreparedTx;
    result: VoteCreationResult;
}


const PageStartVote: React.FC<{}> = () => {
    // A private key in devnet
    const privateKey = useInputValue("0xfc8142dc0a6c1dc9102696e7ca730b8c05e233549ea924fafa477f5086d94ac3");
    const [candidates, setCandidates] = useState<CandidateEntry[]>([
        { id: randCandidateId(), description: "test" }
    ]);
    const [userUploadType, setUserUploadType] = useState<"file" | "textbox">("file");
    const [keys, setKeys] = useState("");
    const [loading, setLoading] = useState(false);
    const fileRef = useRef<HTMLInputElement>(null);

    const [doneCount, setDoneCount] = useState(0);
    const [totalCount, setTotalCount] = useState(1);
    const progress = Math.floor(doneCount / totalCount * 100);
    const [progressText, setProgressText] = useState<string | null>(null);

    const [stage, setStage] = useState<StageInit | StageAccountLoaded | StageDataPrepared | StageSended>({ stage: Stage.INIT });

    const loadAccount = async () => {
        try {
            setLoading(true);
            const account = await generateAccountFromPrivateKey(privateKey.value);
            const address = await ccc.Address.fromString(account.address, cccClient);
            const balance = await cccClient.getBalance([address.script]);
            setStage({ stage: Stage.ACCOUNT_LOADED, accountData: { account, address, balance } });
        } catch (e) { console.error(e); alert(e); } finally {
            setLoading(false);

        }
    }

    const doPrepare = async () => {
        try {
            if (stage.stage !== Stage.ACCOUNT_LOADED) {
                alert("Please load your account first");
                return;
            }
            if (candidates.length === 0) { alert("You must provide at least one candidate"); return; }
            setProgressText("Reading data..");
            const pubKeys: RSAPubKey[] = [];
            let stringData;
            if (userUploadType === "file") {
                const files = fileRef.current!.files;
                if (files === null || files.length !== 1) {
                    alert("Please select exact one public key text file");
                    return;
                }
                stringData = await files[0].text();

            } else {
                stringData = keys;
            }

            if (stringData.length === 0) {
                alert("Please provide at least one pubkey!");
                return;
            }
            for (const [line, index] of _(stringData.split("\n")).map((val, idx) => [val.trim(), idx] as [string, number]).value()) {
                if (line === "") continue;
                const parsed = JSON.parse(line) as { n?: string, e?: string };
                if (!parsed.e || !parsed.n) {
                    throw new Error(`Invalid public key at line ${index + 1} (missing e or n)`);
                }
                pubKeys.push({
                    e: convertJWKNumber(parsed.e),
                    n: convertJWKNumber(parsed.n),
                })

            }
            const accountData = stage.accountData;
            const signer = accountData.account.signer;
            const chunkCount = Math.ceil(pubKeys.length / CHUNK_SIZE);
            setTotalCount(1 + chunkCount);
            let candidateTx;
            {
                setProgressText("Generating candidate data..");
                const candidatesData = encodeCandidate(candidates);
                candidateTx = await publishBytesAsCell(candidatesData, accountData.address.script, signer, "candidate");
                setDoneCount(1);
            }
            const pubKeysTx: PreparedTx[] = [];
            for (const [chunk, idx] of _(pubKeys).chunk(CHUNK_SIZE).map((val, idx) => [val, idx] as [RSAPubKey[], number]).value()) {
                setProgressText(`Generating public key data (${idx + 1}/${chunkCount})`);
                const encoded = encodePubKeyArray(chunk);
                pubKeysTx.push(await publishBytesAsCell(encoded, accountData.address.script, signer, "pubkey chunk"));
                setDoneCount(c => c + 1);
            }
            let requiredCkb = BigInt(0);
            requiredCkb += candidateTx.tx.getOutputsCapacity();
            for (const tx of pubKeysTx) requiredCkb += tx.tx.getOutputsCapacity();
            requiredCkb += BigInt(61 + 4 + 36 * pubKeysTx.length);
            setStage({
                stage: Stage.DATA_PREPARED,
                preparedTx: { candidate: candidateTx, pubKeys: pubKeysTx },
                accountData: stage.accountData,
                prompt: `You need at least ${requiredCkb / BigInt(100000000) + BigInt(1)} CKB for these transactions. Make sure you have enough balance`
            })

        } catch (e) {
            console.error(e);
            alert(e);
        } finally {
            setProgressText(null);
        }
    };
    const doStart = async () => {
        if (stage.stage !== Stage.DATA_PREPARED) {
            alert("Bad stage");
            return;
        }
        console.log(stage);
        const txs = stage.preparedTx;
        setTotalCount(1 + 1 + txs.pubKeys.length);
        setDoneCount(0);
        setProgressText("Sending candidate cell..");
        const candidateHash = await txs.candidate.sendTx();
        console.log(candidateHash);
        setDoneCount(1);
        const pubKeyHashes: string[] = [];
        for (const [item, index] of txs.pubKeys.map((val, idx) => [val, idx] as [PreparedTx, number])) {
            setProgressText(`Sending public key cell (${index + 1}/${txs.pubKeys.length})`)
            pubKeyHashes.push(await item.sendTx());
            setDoneCount(c => c + 1);
        }
        setProgressText("Sending public key index cell..");
        const pubKeyIndexData = encodePubkeyIndexCell(pubKeyHashes.map(value => ({
            index: 0,
            txHash: new Uint8Array(bigintConversion.hexToBuf(value, true) as ArrayBuffer)
        })))
        console.log(pubKeyHashes);
        const pubKeyPreparedTx = await publishBytesAsCell(pubKeyIndexData, stage.accountData.account.lockScript, stage.accountData.account.signer, "public key index");
        const pubkeyIndexHash = await pubKeyPreparedTx.sendTx();
        console.log(pubkeyIndexHash);
        setStage({
            stage: Stage.SENDED, accountData: stage.accountData, preparedTx: stage.preparedTx, pubKeyIndexTx: pubKeyPreparedTx, result: {
                candidateCellTxHash: candidateHash,
                publicKeyCellTxHash: pubKeyHashes,
                publicKeyIndexCellTxHash: pubkeyIndexHash
            }
        })
        setProgressText(null);

    };
    const doSaveResult = () => {
        if (stage.stage !== Stage.SENDED) {
            alert("bad stage");
            return;
        }
        const encoder = new TextEncoder();
        const blob = new Blob([
            encoder.encode(JSON.stringify(stage.result))
        ]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'hashes.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
    return <>
        {progressText !== null && <Modal open size="small">
            <Modal.Header>Progress</Modal.Header>
            <Modal.Content>
                <Progress color="green" percent={progress} active label={progressText}></Progress>
            </Modal.Content>
        </Modal>}
        {loading && progressText === null && <Dimmer active page><Loader></Loader></Dimmer>}
        <Message info>
            <Message.Header>Tips</Message.Header>
            <Message.Content>
                You can start a vote by paying some CKB. You need to provide private key of your account.
                <p>Also, information of all candidates, and public keys of all users should be provided</p>
            </Message.Content>
        </Message>
        <Form>
            <Form.Field>
                <label>Private key of administrator</label>
                <Input {...privateKey} disabled={stage.stage >= Stage.ACCOUNT_LOADED}></Input>
            </Form.Field>
            <Form.Button color="green" onClick={loadAccount}>{stage.stage == Stage.INIT ? "Load account" : "Refresh balance"}</Form.Button>
            {(stage.stage === Stage.ACCOUNT_LOADED || stage.stage === Stage.DATA_PREPARED || stage.stage === Stage.SENDED) && <>
                <Form.Field>
                    <label>Remaining balance</label>
                    {(parseFloat(stage.accountData.balance.toString(10)) / 100000000)} CKB
                </Form.Field>
                <Form.Field>
                    <label>Candidates</label>
                    <Table>
                        <Table.Header>
                            <Table.Row>
                                <Table.HeaderCell>ID</Table.HeaderCell>
                                <Table.HeaderCell>Description</Table.HeaderCell>
                            </Table.Row>
                        </Table.Header>
                        <Table.Body>
                            {candidates.map((item, index) => <Table.Row key={uint8ArrToHex(item.id)}>
                                <Table.Cell>{uint8ArrToHex(item.id)}</Table.Cell>
                                <Table.Cell>
                                    <Input disabled={stage.stage !== Stage.ACCOUNT_LOADED} value={item.description} onChange={(_, d) => {
                                        const newArr = [...candidates];
                                        newArr[index].description = d.value;
                                        setCandidates(newArr);
                                    }}></Input>
                                </Table.Cell>
                                <Table.Cell>
                                    <Button disabled={stage.stage !== Stage.ACCOUNT_LOADED} color="red" onClick={() => {
                                        const newArr = [...candidates];
                                        newArr.splice(index, 1);
                                        setCandidates(newArr);
                                    }}>Remove</Button>
                                </Table.Cell>
                            </Table.Row>)}
                            <Table.Row>
                                <Table.Cell colSpan="2">
                                    <Button disabled={stage.stage !== Stage.ACCOUNT_LOADED} color="green" onClick={() => setCandidates(c => [...c, { description: "", id: randCandidateId() }])}>Add</Button>
                                </Table.Cell>
                            </Table.Row>
                        </Table.Body>
                    </Table>
                </Form.Field>
                <Form.Group inline>
                    <label>How to upload user public keys</label>
                    <Form.Radio disabled={stage.stage !== Stage.ACCOUNT_LOADED} label="Upload text file" checked={userUploadType === "file"} onClick={() => setUserUploadType("file")}></Form.Radio>
                    <Form.Radio disabled={stage.stage !== Stage.ACCOUNT_LOADED} label="Directly input in textbox" checked={userUploadType === "textbox"} onClick={() => setUserUploadType("textbox")}></Form.Radio>
                </Form.Group>
                {userUploadType === "file" && <>
                    <Form.Field>
                        <label>File containing public keys</label>
                        <input disabled={stage.stage !== Stage.ACCOUNT_LOADED} type="file" ref={fileRef}></input>
                    </Form.Field>
                    <Message info>
                        <Message.Header>Note</Message.Header>
                        <Message.Content>
                            You need to select a file containing public keys of users who want to vote. One line for one key. Keys should be in JWK format.
                        </Message.Content>
                    </Message>
                </>}
                {userUploadType === "textbox" && <>
                    <Form.Field>
                        <label>Public keys</label>
                        <TextArea disabled={stage.stage !== Stage.ACCOUNT_LOADED} value={keys} onChange={(_, { value }) => setKeys(value as string)}></TextArea>
                    </Form.Field>
                    <Message info>
                        <Message.Header>Note</Message.Header>
                        <Message.Content>
                            Please provide public keys of users who want to vote. One line for one key. Keys should be in JWK format. If there are two many keys, uploading via file is preferred.
                        </Message.Content>
                    </Message>
                </>}
                <Divider></Divider>
                {stage.stage == Stage.ACCOUNT_LOADED && <Form.Button onClick={doPrepare} color="green">
                    Prepare data
                </Form.Button>}
                {stage.stage == Stage.DATA_PREPARED && <>
                    <Message info>
                        <Message.Content>{stage.prompt}</Message.Content>
                    </Message>
                    <Form.Button color="green" onClick={doStart}>
                        Start
                    </Form.Button>
                    <Form.Button color="green" onClick={() => setStage({ stage: Stage.ACCOUNT_LOADED, accountData: stage.accountData })}>
                        Return to data preparation
                    </Form.Button>
                </>}
                {stage.stage === Stage.SENDED && <>
                    <Message info>
                        <Message.Header>Successfully started</Message.Header>
                        <Message.Content>
                            <p>Candidate cell tx hash: {stage.result.candidateCellTxHash}, index 0</p>
                            <p>Public key index cell tx hash: {stage.result.publicKeyIndexCellTxHash}, index 0</p>
                            <p>For other hashes, please save the result JSON</p>
                        </Message.Content>
                    </Message>
                    <Button color="green" onClick={doSaveResult}>Save hashes</Button>
                </>}
            </>}
        </Form>
    </>;
};

export default PageStartVote;
