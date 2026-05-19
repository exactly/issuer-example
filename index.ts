import { encodeAbiParameters, hashTypedData, hexToBigInt, type TypedData, type TypedDataDefinition } from "viem";
import { generatePrivateKey, privateKeyToAccount, type LocalAccount } from "viem/accounts";
import { optimismSepolia } from "viem/chains";
import { P256, WebAuthnP256 } from "ox";

import { createMessage, signMessage } from "./exa-client";
import { generateNonce, host, verifyMessage } from "./issuer-server";

const chain = optimismSepolia;
const factory = "0x98d3E8B291d9E89C25D8371b7e8fFa8BC32E0aEC";
const last4 = "1234";
const userId = "0a1b-0000-0000-0000-000000000000";

await flow(siweOwner());
console.log("\n\n");
await flow(webauthnOwner());

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

function webauthnOwner() {
  const privateKey = P256.randomPrivateKey();
  return {
    ...P256.getPublicKey({ privateKey }),
    owner: {
      signTypedData: async <
        const typedData extends TypedData | Record<string, unknown>,
        primaryType extends keyof typedData | "EIP712Domain" = keyof typedData,
      >(
        typedData: TypedDataDefinition<typedData, primaryType>,
      ) => {
        const { metadata, payload } = WebAuthnP256.getSignPayload({
          challenge: encodeAbiParameters([{ type: "bytes32" }], [hashTypedData(typedData)]),
          userVerification: "required",
          origin: `https://${host}`,
          rpId: host,
        });
        return encodeAbiParameters(
          [
            {
              type: "tuple",
              components: [
                { name: "authenticatorData", type: "bytes" },
                { name: "clientDataJSON", type: "string" },
                { name: "challengeIndex", type: "uint256" },
                { name: "typeIndex", type: "uint256" },
                { name: "r", type: "uint256" },
                { name: "s", type: "uint256" },
              ],
            },
          ],
          [
            {
              authenticatorData: metadata.authenticatorData,
              clientDataJSON: metadata.clientDataJSON,
              challengeIndex: BigInt(metadata.challengeIndex ?? 0),
              typeIndex: BigInt(metadata.typeIndex ?? 0),
              ...P256.sign({ payload, privateKey, hash: true }),
            },
          ],
        );
      },
    },
  };
}
