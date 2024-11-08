"use client";
import 'semantic-ui-css/semantic.min.css';
import { Dimmer, Header, Loader, Tab } from "semantic-ui-react";
import PageGenerateKeyPair from "./pages/PageGenerateKeyPair";
import PageStartVote from './pages/PageStartVote';
import PageUserVote from './pages/PageUserVote';
import { ccc, ccc as cccConnector, ClientPublicTestnet, useCcc } from "@ckb-ccc/connector-react";
import PageConnectWallet from './pages/PageConnectWallet';
import { cccClient } from './ccc-client';
import { useEffect, useState } from 'react';
import __wbg_init from 'signature-tools-wasm';


const Main: React.FC<{}> = () => {

  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!loaded) {
      (async () => {
        try {
          setLoading(true);
          await __wbg_init();
          setLoaded(true);
          console.log("Wasm initialized...");
        } catch (e) {
          alert(`Failed to init wasm module: ${e}`);
        } finally { setLoading(false); }
      })();
    }
  }, [loaded]);

  const { setClient } = useCcc();
  useEffect(() => {
    setClient(cccClient);
  }, [setClient])
  return <div style={{ marginTop: "5%", marginLeft: "10%", marginRight: "10%" }}>
    {loading && <Dimmer page active><Loader active></Loader></Dimmer>}
    <Header as="h1">
      CKB Voting Demo
    </Header>
    <Tab renderActiveOnly={false} panes={[
      {
        menuItem: "Connect Wallet",
        pane: <Tab.Pane key={0}>
          <PageConnectWallet></PageConnectWallet>
        </Tab.Pane>
      },
      {
        menuItem: "Generating Vote KeyPair", pane: <Tab.Pane key={1}>
          <PageGenerateKeyPair></PageGenerateKeyPair>
        </Tab.Pane>
      },
      {
        menuItem: "Start a Vote", pane: <Tab.Pane key={2}>
          <PageStartVote></PageStartVote>
        </Tab.Pane>
      },
      {
        menuItem: "Vote", pane: <Tab.Pane key={4}>
          <PageUserVote></PageUserVote>
        </Tab.Pane>
      }
    ]}></Tab>

  </div>;

}
const MainWrapped: React.FC<{}> = () => {

  return <cccConnector.Provider defaultClient={cccClient}>
    <Main></Main>
  </cccConnector.Provider>
}

export default MainWrapped;
