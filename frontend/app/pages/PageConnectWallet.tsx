import { ccc as cccConnector, useSigner } from "@ckb-ccc/connector-react";
import { useEffect, useRef, useState } from "react";
import { Button, Divider, Form, List } from "semantic-ui-react";
import { cccClient } from "../ccc-client";



const PageConnectWallet: React.FC<{}> = () => {
    const {
        open,
        disconnect,
        wallet,
        signerInfo,
    } = cccConnector.useCcc();
    const [addresses, setAddresses] = useState<string[] | null>(null);
    const [internalAddress, setInternalAddress] = useState("");
    const [recommendedAddress, settRecommendedAddress] = useState("");

    const [balance, setBalance] = useState<bigint>(BigInt(0));
    const [loaded, setLoaded] = useState(false);
    const loadingRef = useRef(false);
    
    useEffect(() => {
        if (signerInfo !== undefined && !loaded && !loadingRef.current) {
            (async () => {
                // loadingRef.current = true;
                const signer = signerInfo.signer;
                const addresses = await signer.getAddressObjs();

                setAddresses(addresses.map(s => s.toString()));
                const result = await cccClient.getBalance(addresses.map(s => s.script));
                console.log("calling, addresses=", addresses, "result=", result);
                setBalance(result);
                setLoaded(true);
                setInternalAddress(await signer.getInternalAddress());
                settRecommendedAddress(await signer.getRecommendedAddress());
                // loadingRef.current = false;
            })();
        }
    }, [loaded, signerInfo]);
    return <>
        {wallet && signerInfo && <>
            <Form>
                <Form.Group widths={3}>
                    <Form.Field>
                        <label>Wallet name</label>
                        <p>{wallet.name}</p>
                    </Form.Field>
                    <Form.Field>
                        <label>Signer name</label>
                        <p>{signerInfo.name}</p>
                    </Form.Field>
                    <Form.Field>
                        <label>Balance in CKB</label>
                        <p>{parseFloat(balance.toString()) / 100000000}</p>
                    </Form.Field>
                </Form.Group>
                <Form.Field>
                    <label>Recommended address</label>
                    <p>{recommendedAddress}</p>
                </Form.Field>
                <Form.Field>
                    <label>Internal address</label>
                    <p>{internalAddress}</p>
                </Form.Field>
                {addresses !== null && <Form.Field>
                    <label>Addresses</label>
                    <List>
                        {addresses.map(item => <List.Item key={item}>{item}</List.Item>)}
                    </List>
                </Form.Field>}
            </Form>
            <Divider></Divider>
            <Button color="red" onClick={() => disconnect()}>Disconnect</Button>
        </>}
        {!wallet && <>
            <Button onClick={open} color="green">Connect to wallet</Button>
        </>}
    </>
};

export default PageConnectWallet;
