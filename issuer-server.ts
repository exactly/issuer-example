import { createPublicClient, http, type Address, type Hex } from "viem";
import * as chains from "viem/chains";
import { generateSiweNonce, parseSiweMessage } from "viem/siwe";

export const host = "api.example.xyz";

const nonces = new Map<string, string>();
const accounts = new Map<string, Address>();

export function generateNonce({ userId }: { userId: string }) {
  const nonce = generateSiweNonce();
  nonces.set(nonce, userId);
  return nonce;
}

export async function verifyMessage({
  account,
  message,
  signature,
}: {
  account: Address;
  message: string;
  signature: Hex;
}) {
  const { chainId, nonce, statement } = parseSiweMessage(message);
  if (!chainId || !nonce || !statement) throw new Error("bad message");

  // nonce validation
  const userId = nonces.get(nonce);
  if (!userId) throw new Error("bad nonce");
  nonces.delete(nonce);

  // statement validation
  const match =
    /^I authorize this account to be linked with the card ending in (?<last4>\d{4}) for my user \((?<userId>[0-9a-f-]+)\)$/.exec(
      statement,
    );
  const last4 = match?.groups?.last4;
  if (!last4 || match?.groups?.userId !== userId) throw new Error("bad statement");

  const publicClient = createPublicClient({
    chain: Object.values(chains).find((chain) => chain.id === chainId),
    transport: http(/* TODO pass rpc url by `chainId` */),
  });

  const verified = await publicClient.verifySiweMessage({
    address: account,
    domain: host,
    scheme: "https",
    message,
    nonce,
    signature,
  });
  if (verified) accounts.set(`${userId}:${last4}`, account);
  return verified;
}
