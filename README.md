# CKB Vote demo

A simple demo DApp to implement decentralized voting on CKB.

## Projects
- `/frontend`: The frontend app, for users to generate their signature key pair, to vote, and for administrator to start a vote
- `/contracts/ring-signature-verify`: The smart contract, used for veryfing ring signature that was published on chain, so we only accept votes with valid signature
- `/contract-tests`: Tests for the smart contract, based on commpiled binary
- `/vote-counting`: Tools for counting votes
- `/signature-tools`: Rust library for creating ring signature
- `/signature-tools-wasm`: Wasm wrapper for `/signature-tools`, so able to be used in browser
- `/ckb-vote-test-tool`: General testing tool, generates a lot of key pairs, sign their vote result, and publish them onto block chain

## How to use?

Make sure you have clang and offckb installed.

```bash
make build
cd frontend
offckb deploy
yarn dev
```

## For users
- Users should access the website and generate their keypair, and send the public key to administrator
- After an administrator started the vote, users can access the website and send their vote, using balance in their omnilock account
- Users can counting votes by running `vote-counting` tool, providing necessary information publicized by administrator
## For administrator
- Collect public keys of all users who want to vote
- Start a vote by uploading public keys of users, paying the needed CKB with an Omnilock account
- Publicize public_key_index_cell_hash and candidate_cell_hash, and code hash of the smart contract
