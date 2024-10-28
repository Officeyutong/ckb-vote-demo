"use client";
import 'semantic-ui-css/semantic.min.css';
import { Header, Tab } from "semantic-ui-react";
import PageGenerateKeyPair from "./pages/PageGenerateKeyPair";
import PageStartVote from './pages/PageStartVote';
import PageUserVote from './pages/PageUserVote';
import { ccc, ccc as cccConnector, ClientPublicTestnet, useCcc } from "@ckb-ccc/connector-react";
import PageConnectWallet from './pages/PageConnectWallet';
import { cccClient } from './ccc-client';
import { useEffect } from 'react';


const Main: React.FC<{}> = () => {

  const { setClient } = useCcc();
  useEffect(() => {
    setClient(cccClient);
  }, [setClient])
  return <div style={{ marginTop: "5%", marginLeft: "10%", marginRight: "10%" }}>
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
        menuItem: "Generating KeyPair", pane: <Tab.Pane key={1}>
          <PageGenerateKeyPair></PageGenerateKeyPair>
        </Tab.Pane>
      },
      {
        menuItem: "Start a vote", pane: <Tab.Pane key={2}>
          <PageStartVote></PageStartVote>
        </Tab.Pane>
      },
      {
        menuItem: "Vote", pane: <Tab.Pane key={3}>
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
