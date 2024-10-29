import { ccc, CellDepInfoLike, KnownScript, Script } from "@ckb-ccc/connector-react";
import offCKB, { Network } from "../offckb.config";

export const DEVNET_SCRIPTS: Record<
  string,
  Pick<Script, "codeHash" | "hashType"> & { cellDeps: CellDepInfoLike[] }
> = {
  [KnownScript.Secp256k1Blake160]:
    offCKB.systemScripts.secp256k1_blake160_sighash_all!.script,
  [KnownScript.Secp256k1Multisig]:
    offCKB.systemScripts.secp256k1_blake160_multisig_all!.script,
  [KnownScript.AnyoneCanPay]: offCKB.systemScripts.anyone_can_pay!.script,
  [KnownScript.OmniLock]: offCKB.systemScripts.omnilock!.script,
  [KnownScript.XUdt]: offCKB.systemScripts.xudt!.script,
};

export function buildCccClient(network: Network) {
  console.log("Creating client with network: ", network);
  const client =
    network === "mainnet"
      ? new ccc.ClientPublicMainnet()
      : network === "testnet"
        ? new ccc.ClientPublicTestnet()
        : new ccc.ClientPublicTestnet(offCKB.rpcUrl, undefined, DEVNET_SCRIPTS);

  return client;
}

export const cccClient = buildCccClient(offCKB.currentNetwork);
