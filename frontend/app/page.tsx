"use client";
import 'semantic-ui-css/semantic.min.css';
import { Header, Tab } from "semantic-ui-react";
import PageGenerateKeyPair from "./pages/PageGenerateKeyPair";
import PageStartVote from './pages/PageStartVote';
import PageUserVote from './pages/PageUserVote';




const Main: React.FC<{}> = () => {

  return <div style={{ marginTop: "5%", marginLeft: "10%", marginRight: "10%" }}>
    <Header as="h1">
      CKB Voting Demo
    </Header>
    <Tab renderActiveOnly={false} panes={[
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
export default Main;
