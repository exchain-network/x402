# @exchain-network/x402

Pay any [x402](https://x402.org) seller from a wallet your agent cannot drain.

The wallet is a standard Safe 1.4.1 on Base. Its owners are your agent's key and Exchain's attested enclaves, and every owner must sign. Before the enclaves sign a payment, Exchain checks it against your mandate: per-seller and per-agent limits, and which sellers you allow. Your owner address is the Safe's only module, so you can always withdraw or remove Exchain without us.

The agent cannot pay without Exchain, Exchain cannot pay without the agent, and the seller receives a signed guard receipt it can verify.

```
npm install @exchain-network/x402 @x402/fetch @x402/evm viem
```

`@x402/fetch`, `@x402/evm` (2.29 or newer) and `viem` are peer dependencies, so your app and this package share one copy.

## Pay

```js
import { privateKeyToAccount } from "viem/accounts";
import { registerX402Wallet, exchainFetch } from "@exchain-network/x402";

const cosign = { url: "https://cosign.exchain.network", token: process.env.EXCHAIN_NODE_TOKEN };
const agent = privateKeyToAccount(process.env.AGENT_KEY);   // never leaves your machine
const owner = privateKeyToAccount(process.env.OWNER_KEY);   // signs the consent once; can withdraw alone

const wallet = await registerX402Wallet(cosign, {
  nodeId: "my-node",
  orgId: "my-org",
  agentAddress: agent.address,
  ownerAddress: owner.address,
  permit2Cap: "100000000",
  governedAsset: { id: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", decimals: 6 }, // USDC on Base
  constitution: {
    template: "x402-micro",
    params: { perTxCap: "1000000", daily: "50000000", perSeller: "20000000", perAgent: "50000000", envelope: "500000000", burstPerMinute: 60 },
  },
  sellers: [{ domain: "api.seller.example" }],
  unsignedSellers: "refuse",
}, { owner });

// Send USDC to wallet.walletAddress, then:
const pay = exchainFetch({
  cosign,
  walletId: wallet.walletId,
  safe: wallet.walletAddress,
  agent,
  context: () => ({ agentIdentifier: "my-agent" }),
});
const res = await pay("https://api.seller.example/forecast");
```

Exchain deploys the Safe at registration, at the address fixed by exactly this setup. Amounts are in the token's smallest unit (USDC has 6 decimals, so `1000000` is $1).

A refused payment rejects with `ExchainDenied { code, detail, decisionId }`, and nothing is signed. Codes include `per_tx_cap`, `daily_outflow`, `payee_unpinned` and `registry_gate`.

## API

- `registerX402Wallet(cosign, registration, { owner })`: registers the wallet and returns `{ walletId, walletAddress, owners }`. The owner signs a consent message, so nobody can register a Safe in your name.
- `exchainFetch(opts)`: a `fetch` that answers x402 `402` responses with a guarded payment.
- `exchainEvmSigner({ safe, agent, walletId, cosign, context })`: the same signer as an `@x402/evm` `ClientEvmSigner`, for an `x402Client` you already have (`registerExactEvmScheme(client, { signer })`).
  - `@x402/*` 2.29 caps every payment at $1 before any signer runs. Call `client.setSpendControls(false)` on a guarded wallet's client, so your mandate is the only cap and an over-cap payment comes back as `ExchainDenied` with a decision id.
  - `exchainFetch` and `x402Fetch` do this for you.
- `exchainShadowSigner({ account, walletId, cosign, onDecision })` with `x402Fetch(signer)`: shadow mode for an existing wallet. Register with `shadow: true` and your agent's own address. Every payment is judged and recorded but none is blocked, and `onDecision` reports what would have been refused.
- `verifyGuardReceipt(jws, { didDocument?, issuers?, expect? })`: for sellers. Every guarded payment carries a receipt at `paymentPayload.extensions["exchain-guard"].receipt` (`GUARD_EXTENSION`).
  - Only issuers in `issuers` are accepted. The default is `EXCHAIN_ISSUER` (`did:web:cosign.exchain.network`).
  - The EdDSA signature is checked against that issuer's `did:web` document, offline when you pass `didDocument`.
  - The fields in `expect` (`payTo`, `amount`, `payer`) are compared.
- `safeMessageHash(safe, typedData)`, `paymentOf(typedData)`, `nonceOf(typedData)`, `signedOfferFor(paymentRequired, chosen)`: lower-level helpers.

## Sellers you allow

List sellers with `sellers: [{ domain, keys? }]`. With `unsignedSellers: "refuse"`, or `{ allowUnder }` for small amounts, Exchain pays only a seller whose signed x402 `offer-receipt` offer matches the payment. The offer must be signed by a key in your mandate or in the seller's `/.well-known/did.json`. The client forwards the offer automatically.

## Fees

Exchain charges a network fee of every guarded payment that settles, in USDC from the Safe. Once $1 is due, the next payment first signs one fee authorization, then pays. `GET /v1/x402/wallets/{walletId}/fees` shows what accrued, what was paid and what is due.

## What can leave the wallet

`GET /v1/wallets/{walletId}/bound` returns a signed statement read on chain:
- `honest`: what the mandate still allows;
- `worstCase`: what could leave if every key were stolen, which is the Safe's balance plus its Permit2 approval.

## Settlement

The Safe signs with one 65-byte signature per owner, which USDC verifies through ERC-1271. Any `@x402/evm` facilitator settles it, including a self-hosted one. Both EIP-3009 and Permit2 sellers work, and the Permit2 approval is set in the Safe's setup (`permit2Cap`).

## Requirements

- Node.js 20 or newer
- an Exchain node token
- USDC on Base

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
