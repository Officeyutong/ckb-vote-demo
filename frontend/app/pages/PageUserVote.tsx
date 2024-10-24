import { Button, Dimmer, Form, Input, Loader, Message, Modal, Progress, Table } from "semantic-ui-react";
import { AccountData, CandidateEntry, decodeCandidate, decodePubKeyArray, decodePubkeyIndexCell, generateAccountFromPrivateKey, PubkeyIndexEntry, RSAPubKey, uint8ArrToHex, useInputValue } from "../utils";
import { useState } from "react";
import { cccClient } from "../ccc-client";
import { ccc } from "@ckb-ccc/core";
import { hexToBuf } from "bigint-conversion";
import _ from "lodash";

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
    accountData: AccountData;
    pubKeyIndex: PubkeyIndexEntry[];
    pubKeys: { index: PubkeyIndexEntry; keys: RSAPubKey[]; }[];
}

interface StageVoted extends Omit<StageCandidateLoaded, "stage"> {
    stage: Stage.VOTED;
}

const PageUserVote: React.FC<{}> = () => {
    const [stage, setStage] = useState<StageInit | StageCandidateLoaded | StageVoted>({ stage: Stage.INIT });

    const [doneCount, setDoneCount] = useState(0);
    const [totalCount, setTotalCount] = useState(1);
    const [progressText, setProgressText] = useState<string | null>(null);

    // A private key from devnet account
    const accountPrivateKey = useInputValue("0xa5808e79c243d8e026a034273ad7a5ccdcb2f982392fd0230442b1734c98a4c2");
    const candidateHash = useInputValue("0x25ac3acb04e0ff302d2af483e04128470e1f71f1b44f22a8037e13662a960fcd");
    const publicKeyIndexCell = useInputValue("0x245bad49116aa12aa0e400a65fb1374f1e131451f81f766016cca78eec3f85e0");
    const [loading, setLoading] = useState(false);
    const [selectedCandidate, setSelectedCandidate] = useState<string | null>(null);
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
                                        {idStr === selectedCandidate ? <Button size="small" color="red" disabled>Selected</Button> : <Button size="small" color="green" onClick={() => setSelectedCandidate(idStr)}>Select</Button>}
                                    </Table.Cell>
                                </Table.Row>;
                            })}
                        </Table.Body>
                    </Table>
                </Form.Field>
            </>}
        </Form>
    </>
};

export default PageUserVote;
