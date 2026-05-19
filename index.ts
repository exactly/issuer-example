import { hexToBigInt } from "viem";
import { generatePrivateKey, privateKeyToAccount, type LocalAccount } from "viem/accounts";
import { optimismSepolia } from "viem/chains";

import { createMessage, signMessage } from "./exa-client";
import { generateNonce, host, verifyMessage } from "./issuer-server";

const chain = optimismSepolia;
const factory = "0x98d3E8B291d9E89C25D8371b7e8fFa8BC32E0aEC";
const last4 = "1234";
const userId = "0a1b-0000-0000-0000-000000000000";

await flow(siweOwner());

async function flow({ owner, x, y }: { owner: Pick<LocalAccount, "signTypedData">; x: bigint; y: bigint }) {
  const nonce = generateNonce({ userId }); // issuer server

  const message = createMessage({ chainId: chain.id, host, last4, nonce, userId, factory, x, y }); // exa client
  console.log(message);
  const { account, signature } = await signMessage({ chain, message, factory, x, y, owner }); // exa client

  const verified = await verifyMessage({ message, signature, account }); // issuer server

  console.log({ verified });
}

function siweOwner() {
  const owner = privateKeyToAccount(generatePrivateKey());
  return { owner, x: hexToBigInt(owner.address), y: 0n };
}
