import {
  checksumAddress,
  createPublicClient,
  encodeAbiParameters,
  encodeFunctionData,
  encodePacked,
  hashMessage,
  http,
  keccak256,
  padHex,
  parseAbi,
  parseAbiParameters,
  serializeErc6492Signature,
  slice,
  type Address,
  type Chain,
  type LocalAccount,
} from "viem";

import { createSiweMessage } from "viem/siwe";

export function createMessage({
  chainId,
  factory,
  host,
  last4,
  nonce,
  userId,
  x,
  y,
}: {
  chainId: number;
  factory: Address;
  host: string;
  last4: string;
  nonce: string;
  userId: string;
  x: bigint;
  y: bigint;
}) {
  const issuedAt = new Date();
  return createSiweMessage({
    statement: `I authorize this account to be linked with the card ending in ${last4} for my user (${userId})`,
    uri: `https://${host}/v1/issuing/users/${userId}/signatures/verify`,
    expirationTime: new Date(issuedAt.getTime() + 5 * 60_000),
    address: deriveAddress({ factory, x, y }),
    domain: host,
    scheme: "https",
    version: "1",
    issuedAt,
    chainId,
    nonce,
  });
}

export async function signMessage({
  chain,
  factory,
  message,
  owner,
  x,
  y,
}: {
  chain: Chain;
  factory: Address;
  message: string;
  owner: Pick<LocalAccount, "signTypedData">;
  x: bigint;
  y: bigint;
}) {
  const account = deriveAddress({ factory, x, y });
  const factoryData = encodeFunctionData({
    functionName: "createAccount",
    args: [0n, [{ x, y }]],
    abi: parseAbi(["function createAccount(uint256 salt, (uint256 x, uint256 y)[] owners) returns (address)"]),
  });
  const plugins = await createPublicClient({ chain, transport: http() }).readContract({
    address: account,
    functionName: "getInstalledPlugins",
    abi: parseAbi(["function getInstalledPlugins() view returns (address[])"]),
    factoryData,
    factory,
  });
  const ownerPlugin = plugins.at(-1);
  if (!ownerPlugin) throw new Error("missing plugin");
  return {
    account,
    signature: serializeErc6492Signature({
      address: factory,
      data: factoryData,
      signature: encodePacked(
        ["uint8", "bytes"],
        [
          0,
          await owner.signTypedData({
            domain: {
              chainId: chain.id,
              name: "Webauthn Owner Plugin",
              version: "1.0.0",
              verifyingContract: account,
              salt: padHex(ownerPlugin, { dir: "right" }),
            },
            types: { AlchemyModularAccountMessage: [{ name: "message", type: "bytes" }] },
            primaryType: "AlchemyModularAccountMessage",
            message: { message: encodeAbiParameters(parseAbiParameters("bytes32"), [hashMessage(message)]) },
          }),
        ],
      ),
    }),
  };
}

function deriveAddress({ factory, x, y }: { factory: Address; x: bigint; y: bigint }) {
  const accountImplementation = "0x0046000000000151008789797b54fdb500E2a61e";
  const initCodeHashERC1967 = keccak256(
    encodePacked(
      ["bytes", "address", "bytes"],
      [
        "0x603d3d8160223d3973",
        accountImplementation,
        "0x60095155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3",
      ],
    ),
  );
  return checksumAddress(
    slice(
      keccak256(
        encodePacked(
          ["uint8", "address", "bytes32", "bytes32"],
          [
            0xff,
            factory,
            keccak256(
              encodeAbiParameters(parseAbiParameters("uint256, bytes"), [
                0n,
                encodeAbiParameters(parseAbiParameters("(uint256 x, uint256 y)[]"), [[{ x, y }]]),
              ]),
            ),
            initCodeHashERC1967,
          ],
        ),
      ),
      12,
    ),
  );
}
