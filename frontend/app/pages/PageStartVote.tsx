import { useState } from "react";
import { Message } from "semantic-ui-react";

const PageStartVote: React.FC<{}> = () => {
    const [privKey, setPrivKey] = useState<string>("");

    return <>
        <Message info>
            <Message.Header>Tips</Message.Header>
            <Message.Content>
                You can start a vote by paying some CKB. You need to provide private key of your account.
            </Message.Content>
        </Message>
    </>;
};

export default PageStartVote;
