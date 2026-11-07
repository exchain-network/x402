// @exchain-network/x402: pay any x402 seller from an Exchain-guarded Safe.
//
//   const pay = exchainFetch({ cosign: { url, token }, walletId, safe, agent });
//   const res = await pay("https://seller.example/api");
//
// The Safe's owners are the agent and every Exchain enclave, threshold all of
// them; `signTypedData` signs the Safe message hash with the agent key, asks
// Exchain for the enclaves' signatures, and returns every owner's signature
// sorted by owner address (a non-65-byte signature, so facilitators settle it
// through ERC-1271). When Exchain's fees are due, the signer
// first signs the one fee authorization Exchain asks for, then pays.

import { AsyncLocalStorage } from "node:async_hooks";
import { hashTypedData, getAddress, toHex } from "viem";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";

/** Exchain refused the payment: `code` is the denial code (`per_tx_cap`, `body_mismatch`, …). */
export class ExchainDenied extends Error {
  constructor(code, detail, decisionId, body) {
    super(`exchain denied the payment: ${code}${detail ? ` (${detail})` : ""}`);
    this.name = "ExchainDenied";
    this.code = code;
    this.detail = detail;
    this.decisionId = decisionId;
    this.body = body;
  }
}

/** The hash every Safe owner signs for `typedData` (Safe 1.4.1 `CompatibilityFallbackHandler`). */
export function safeMessageHash(safe, typedData) {
  return hashTypedData({
    domain: { chainId: Number(typedData.domain.chainId), verifyingContract: safe },
    types: { SafeMessage: [{ name: "message", type: "bytes" }] },
    primaryType: "SafeMessage",
    message: { message: hashTypedData(typedData) },
  });
}

const plain = (value) =>
  JSON.parse(JSON.stringify(value, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

/** What the typed data pays: payee, amount and token. */
export function paymentOf(typedData) {
  const m = typedData.message;
  const chainId = Number(typedData.domain.chainId);
  const [to, amount, token] =
    typedData.primaryType === "PermitWitnessTransferFrom"
      ? [m.witness.to, m.permitted.amount, m.permitted.token]
      : [m.to, m.value, typedData.domain.verifyingContract];
  return {
    counterparty: `eip155:${chainId}:${getAddress(to)}`,
    amount: BigInt(amount).toString(),
    asset: `eip155:${chainId}/erc20:${token.toLowerCase()}`,
  };
}

const payment = new AsyncLocalStorage();

/** The payment payload extension that carries the guard receipt. */
export const GUARD_EXTENSION = "exchain-guard";

/** The `did:web` of Exchain's production service, the default trusted receipt issuer. */
export const EXCHAIN_ISSUER = "did:web:cosign.exchain.network";

/** The seller's signed offer (`offer-receipt`) for the requirement the client chose, if it sent one. */
export function signedOfferFor(paymentRequired, chosen) {
  const offers = paymentRequired?.extensions?.["offer-receipt"]?.info?.offers ?? [];
  const accepts = paymentRequired?.accepts ?? [];
  const same = (a, b) => String(a ?? "").toLowerCase() === String(b ?? "").toLowerCase();
  const index = accepts.findIndex((a) => a === chosen || (same(a.payTo, chosen.payTo) && same(a.asset, chosen.asset) && a.network === chosen.network && String(a.amount) === String(chosen.amount)));
  return offers.find((o) => o.acceptIndex === index) ?? offers.find((o) => o.payload && same(o.payload.payTo, chosen.payTo) && String(o.payload.amount) === String(chosen.amount));
}

const unb64 = (s) => Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");

/**
 * Checks a guard receipt: an EdDSA JWS whose `kid` is a key of the issuer's
 * `did:web` document. The issuer must be one of `issuers` (Exchain's
 * production service by default); its document is `didDocument` when given,
 * otherwise fetched from `https://<host>/.well-known/did.json`. Returns the
 * payload; throws when the issuer, the signature, the key or `expect` (fields
 * that must match) does not hold.
 */
export async function verifyGuardReceipt(jws, { didDocument, issuers = [EXCHAIN_ISSUER], fetch: get = globalThis.fetch, expect = {} } = {}) {
  const [h, p, s] = String(jws).split(".");
  const header = JSON.parse(unb64(h).toString());
  const payload = JSON.parse(unb64(p).toString());
  if (header.alg !== "EdDSA" || !header.kid?.startsWith("did:web:")) throw new Error("guard receipt: not an EdDSA did:web JWS");
  const did = header.kid.split("#")[0];
  if (!issuers.includes(did)) throw new Error(`guard receipt: issuer ${did} is not trusted`);
  const doc = didDocument ?? (await get(`https://${decodeURIComponent(did.slice("did:web:".length))}/.well-known/did.json`).then((r) => r.json()));
  const method = doc.id === did && doc.verificationMethod?.find((m) => m.id === header.kid);
  if (!method?.publicKeyJwk) throw new Error("guard receipt: the issuer's document does not hold its key");
  const key = await crypto.subtle.importKey("jwk", method.publicKeyJwk, { name: "Ed25519" }, false, ["verify"]);
  if (!(await crypto.subtle.verify({ name: "Ed25519" }, key, unb64(s), new TextEncoder().encode(`${h}.${p}`)))) throw new Error("guard receipt: bad signature");
  for (const [k, v] of Object.entries(expect)) {
    if (String(payload[k]).toLowerCase() !== String(v).toLowerCase()) throw new Error(`guard receipt: ${k} is ${payload[k]}, expected ${v}`);
  }
  return payload;
}

async function post({ url, token }, path, body, headers = {}) {
  const res = await fetch(`${url.replace(/\/$/, "")}${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { status: res.status, answer: await res.json().catch(() => ({})) };
}

async function cosign(endpoint, body, settleFee, path = "/v1/x402/cosign") {
  const { status, answer } = await post(endpoint, path, body, { "idempotency-key": body.batchId });
  if (status === 402 && answer.error === "fee_due" && settleFee) {
    await settleFee(answer.fee);
    return cosign(endpoint, body, undefined, path);
  }
  if (status === 409) {
    const code = answer.denied === "member_denied" ? answer.members?.[0]?.denied : answer.denied;
    const denied = new ExchainDenied(code, answer.detail ?? answer.members?.[0]?.reasonEnglish, answer.decisionId, answer);
    const call = payment.getStore();
    if (call) call.denied = denied;
    throw denied;
  }
  if (status !== 200) {
    throw new Error(`exchain co-sign answered ${status}: ${answer.error ?? ""} ${answer.detail ?? ""}`.trim());
  }
  return answer;
}

/** The authorization nonce as 32 bytes of 0x hex: the request's `batchId`. */
export function nonceOf(typedData) {
  const n = typedData.message.nonce;
  return typedData.primaryType === "PermitWitnessTransferFrom" ? toHex(BigInt(n), { size: 32 }) : n.toLowerCase();
}

function request({ walletId, typedData, context, agentSignature }) {
  const ctx = context?.() ?? {};
  const resource = ctx.resource ?? payment.getStore()?.resource;
  const offer = ctx.offer ?? payment.getStore()?.offer;
  const batchId = nonceOf(typedData);
  return {
    batchId,
    walletId,
    typedData: plain({ domain: typedData.domain, types: typedData.types, primaryType: typedData.primaryType, message: typedData.message }),
    ...(agentSignature ? { agentSignature } : {}),
    intent: {
      purchaseId: ctx.purchaseId ?? batchId,
      ...paymentOf(typedData),
      agentIdentifier: ctx.agentIdentifier ?? "",
      ...(resource ? { resource } : {}),
      ...(ctx.paymentIdentifier ? { paymentIdentifier: ctx.paymentIdentifier } : {}),
      ...(offer ? { offer } : {}),
    },
  };
}

/**
 * A `ClientEvmSigner` for a guarded Safe.
 * `onReceipt` sees each payment's guard receipt, for a client that attaches
 * it to the payload itself (`x402Fetch` does).
 * @param {{ safe: `0x${string}`, agent: import("viem").LocalAccount, walletId: string,
 *           cosign: { url: string, token: string }, context?: () => object,
 *           onReceipt?: (receipt: string) => void }} opts
 */
function feeSettler({ safe, agent, walletId, endpoint }) {
  return async (fee) => {
    const m = fee.typedData.message;
    const typed = { ...fee.typedData, message: { ...m, value: BigInt(m.value), validAfter: BigInt(m.validAfter), validBefore: BigInt(m.validBefore) } };
    const agentSignature = await agent.sign({ hash: safeMessageHash(safe, typed) });
    const { status, answer } = await post(endpoint, "/v1/x402/fees", { walletId, typedData: fee.typedData, agentSignature });
    if (status !== 200) throw new Error(`exchain fee settlement answered ${status}: ${answer.error ?? ""} ${answer.detail ?? ""}`.trim());
  };
}

export function exchainEvmSigner({ safe, agent, walletId, cosign: endpoint, context, onReceipt }) {
  const settleFee = feeSettler({ safe, agent, walletId, endpoint });
  return {
    address: getAddress(safe),
    async signTypedData(typedData) {
      const agentSignature = await agent.sign({ hash: safeMessageHash(safe, typedData) });
      const answer = await cosign(endpoint, request({ walletId, typedData, context, agentSignature }), settleFee);
      const call = payment.getStore();
      if (call && answer.receipt) call.receipt = answer.receipt;
      if (answer.receipt) onReceipt?.(answer.receipt);
      return answer.signature;
    },
  };
}

/** USDC (FiatToken v2.2) and its EIP-712 domain name, per chain. */
export const USDC = {
  84532: { address: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", name: "USDC" },
  8453: { address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", name: "USD Coin" },
  11155111: { address: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", name: "USDC" },
  1: { address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", name: "USD Coin" },
  421614: { address: "0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d", name: "USD Coin" },
  42161: { address: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", name: "USD Coin" },
  11155420: { address: "0x5fd84259d66Cd46123540766Be93DFE6D43130D7", name: "USDC" },
  10: { address: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", name: "USD Coin" },
  80002: { address: "0x41E94Eb019C0762f9Bfcf9Fb1E58725BfB0e7582", name: "USDC" },
  137: { address: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", name: "USD Coin" },
};

/**
 * Pays `amount` (USDC minor units) from the guarded Safe to `payTo` directly,
 * outside x402: one EIP-3009 authorization, valid `validFor` seconds (at most
 * 600), checked against the mandate and co-signed by Exchain. With `relay`
 * Exchain sends it and the answer carries `relayed.txHash`; either way
 * `transaction` (`{to, data}`) can be sent by any account until it expires.
 * Throws `ExchainDenied` on a refusal.
 * @param {{ safe: `0x${string}`, agent: import("viem").LocalAccount, walletId: string,
 *           cosign: { url: string, token: string }, chainId: number }} wallet
 * @param {{ payTo: `0x${string}`, amount: bigint | string, agentIdentifier?: string,
 *           purchaseId?: string, reference?: string, validFor?: number, relay?: boolean }} payment
 */
export async function exchainPay({ safe, agent, walletId, cosign: endpoint, chainId }, { payTo, amount, agentIdentifier = "", purchaseId, reference, validFor = 300, relay = true }) {
  const usdc = USDC[chainId];
  if (!usdc) throw new Error(`exchainPay: no USDC on chain ${chainId}`);
  const nonce = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const typedData = {
    domain: { name: usdc.name, version: "2", chainId, verifyingContract: usdc.address },
    types: {
      TransferWithAuthorization: [
        { name: "from", type: "address" },
        { name: "to", type: "address" },
        { name: "value", type: "uint256" },
        { name: "validAfter", type: "uint256" },
        { name: "validBefore", type: "uint256" },
        { name: "nonce", type: "bytes32" },
      ],
    },
    primaryType: "TransferWithAuthorization",
    message: { from: getAddress(safe), to: getAddress(payTo), value: BigInt(amount), validAfter: 0n, validBefore: BigInt(Math.floor(Date.now() / 1000) + validFor), nonce },
  };
  const agentSignature = await agent.sign({ hash: safeMessageHash(safe, typedData) });
  const body = {
    batchId: nonce,
    walletId,
    typedData: plain(typedData),
    agentSignature,
    relay,
    intent: { purchaseId: purchaseId ?? nonce, ...paymentOf(typedData), agentIdentifier, ...(reference ? { reference } : {}) },
  };
  return cosign(endpoint, body, feeSettler({ safe, agent, walletId, endpoint }), "/v1/evm/cosign");
}

/**
 * Shadow mode: the agent keeps paying with its own account; every payment is
 * first judged by Exchain and journalled. `onDecision` sees each answer; a
 * would-be refusal is reported, never enforced.
 */
export function exchainShadowSigner({ account, walletId, cosign: endpoint, context, onDecision }) {
  return {
    address: account.address,
    async signTypedData(typedData) {
      try {
        onDecision?.({ allowed: true, ...(await cosign(endpoint, request({ walletId, typedData, context }))) });
      } catch (e) {
        onDecision?.(e instanceof ExchainDenied ? { allowed: false, code: e.code, detail: e.detail, decisionId: e.decisionId } : { error: e });
      }
      return account.signTypedData(typedData);
    },
  };
}

/**
 * `fetch` that pays x402 sellers through `signer` (from either function
 * above). An Exchain refusal rejects with the `ExchainDenied` itself.
 * `spendControls` is `@x402/core`'s own client cap: off by default, so the
 * mandate is the cap and a shadow wallet pays as it did before 2.29.0; pass
 * the library's `SpendControls` to keep one beside the mandate.
 */
export function x402Fetch(signer, { fetch: base = globalThis.fetch, spendControls = false } = {}) {
  const client = new x402Client();
  client.setSpendControls(spendControls);
  registerExactEvmScheme(client, { signer });
  client.onBeforePaymentCreation(async ({ paymentRequired, selectedRequirements }) => {
    const call = payment.getStore();
    if (call) call.offer = signedOfferFor(paymentRequired, selectedRequirements);
  });
  client.registerExtension({
    key: GUARD_EXTENSION,
    enrichPaymentPayload: async (payload) => {
      const receipt = payment.getStore()?.receipt;
      return receipt ? { ...payload, extensions: { ...payload.extensions, [GUARD_EXTENSION]: { receipt } } } : payload;
    },
  });
  const paid = wrapFetchWithPayment(base, client);
  return (input, init) => {
    const call = { resource: typeof input === "string" ? input : (input?.url ?? String(input)) };
    return payment.run(call, () =>
      paid(input, init).catch((e) => {
        throw call.denied ?? e;
      }),
    );
  };
}

/** `fetch` that pays x402 sellers from a guarded Safe. */
export function exchainFetch(opts) {
  return x402Fetch(exchainEvmSigner(opts), opts);
}

/**
 * `POST /v1/x402/wallets`. The owner module moves funds alone, so the service
 * asks `owner` (a viem account, or anything with `signMessage`) to sign its
 * consent to exactly this Safe; shadow registrations need no owner.
 */
export async function registerX402Wallet({ url, token }, registration, { owner } = {}) {
  const post = (body) =>
    fetch(`${url.replace(/\/$/, "")}/v1/x402/wallets`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  let res = await post(registration);
  let answer = await res.json();
  if (res.status === 400 && answer.error === "owner_signature_required" && owner) {
    const ownerSignature = await owner.signMessage({ message: answer.detail });
    res = await post({ ...registration, ownerSignature });
    answer = await res.json();
  }
  if (res.status !== 201 && res.status !== 200) {
    throw new Error(`registration answered ${res.status}: ${answer.error ?? ""} ${answer.detail ?? ""}`.trim());
  }
  return answer;
}
