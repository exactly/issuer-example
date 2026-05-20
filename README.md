# Issuer account linking example

This example shows the end-to-end flow for linking a cardholder to an onchain account, with the issuer verification path called out.

The issuer is responsible for:

- creating a one-time SIWE nonce for an authenticated user
- checking that the signed message belongs to the user associated with the nonce
- verifying the SIWE signature against the derived account
- storing the linked account for future card operations

## Issuer code

The issuer logic lives in [`issuer-server.ts`](issuer-server.ts).

`generateNonce({ userId })`

Creates a one-time nonce and associates it with the authenticated issuer user. In production, this should be stored with an expiration time.

`verifyMessage({ account, message, signature })`

Validates the returned SIWE message:

- parses `chainId`, `nonce`, and `statement`
- rejects unknown or reused nonces
- confirms the statement's user matches the user associated with the nonce
- verifies that the account in the message produced a valid SIWE signature
- records the verified account link in the issuer's system

## Compared with the existing implementation

Compared with the existing implementation, this flow is simpler on the backend:

- one SIWE verification path covers both private-key and WebAuthn/P-256 owners
- the signed SIWE address is the derived account, so the statement no longer includes the account address
- the backend no longer verifies WebAuthn assertions or decodes credential public keys
- WebAuthn-specific backend dependencies are no longer used
- account linking is the only flow shown here; operation signing is separate

In practice, this means configuring an RPC URL for the supported network. The verifier uses it during SIWE validation to check the smart account signature, including accounts that have not been deployed yet.

## Integration notes

- Set `host` to the domain users should recognize in the signing prompt, and use the same value when verifying the message.
- Store nonces and verified account links in the issuer database.
- Apply nonce expiration, replay protection, and session binding.
- Configure chain support and RPC access for each supported network.
- Record the verified account next to the issuer's internal user and card identifiers.
- Put the verifier behind the authenticated backend.

## Dependencies

The flow is portable at the protocol level. For TypeScript implementations, `viem` is the recommended path and is the only runtime dependency used for issuer verification in this example.

The issuer backend no longer uses WebAuthn server dependencies. WebAuthn/P-256 owners are handled through the same SIWE verification path as private-key owners.

## Run it

```sh
npm install
npm run run
```

The script covers both owner types in this example: a private-key owner and a WebAuthn/P-256 owner. It prints whether each signed message was accepted by the issuer verifier.
