[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Networking](06-networking.md) · [Next: Security considerations →](08-security.md)

---

# JSON-RPC API

## Contents

- [The `VNT` namespace](#the-vnt-namespace)
- [`vnt_getAccountsSupportedDSAs`](#vnt_getaccountssupporteddsas)
- [Sending flexible transactions](#sending-flexible-transactions)
- [Transaction objects](#transaction-objects)
- [Code delegation objects](#code-delegation-objects)
- [Errors](#errors)
- [Not supported](#not-supported)

## The `VNT` namespace

The fork adds the API group `VNT` (`RpcApis.VNT`). Like any non-default group, it must be enabled explicitly:

```bash
besu --rpc-http-enabled --rpc-http-api=ETH,NET,WEB3,VNT ...
```

or in `config.toml`:

```toml
rpc-http-api=["ETH","NET","QBFT","VNT"]
```

The same applies to `--rpc-ws-api`.

## `vnt_getAccountsSupportedDSAs`

Returns the DSAs that this node accepts for account signatures, in the order given by `--accounts-supported-dsas`.
Clients use it to choose an algorithm that the node will accept before they sign.

**Parameters:** none.

**Returns:** an array of DSA names (see [Algorithms](03-cryptography/algorithms.md#identifiers-and-sizes)).

```bash
curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"vnt_getAccountsSupportedDSAs","params":[],"id":1}' http://localhost:8545
```

```json
{"jsonrpc":"2.0","id":1,"result":["SECP256K1","SECP256R1","SECP256K1-MLDSA44","SECP256K1-FALCON512"]}
```

With the default configuration, the result is `["SECP256K1"]`.

> Different nodes of a network may enable different account DSAs. A transaction is accepted into a node's pool only if
> that node enables its DSA. Blocks are *executed* by every node, but a node that has not enabled a DSA rejects
> transactions of that type, including inside blocks. Keep `--accounts-supported-dsas` identical on all validators.

## Sending flexible transactions

Use the standard **`eth_sendRawTransaction`** with the typed envelope described in
[Transactions → Wire encoding](04-transactions.md#wire-encoding):

```bash
curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x42f9…"],"id":1}' http://localhost:8545
```

```json
{"jsonrpc":"2.0","id":1,"result":"0x9f1c…e27a"}
```

The result is the transaction hash, `keccak256(type ‖ rlp(fields))`.

## Transaction objects

Every method that returns transactions (`eth_getTransactionByHash`, `eth_getBlockByNumber` with full transactions,
`eth_getTransactionByBlockHashAndIndex`, `txpool_*`, `eth_subscribe` to pending transactions) returns flexible
transactions with these differences:

| Field | Flexible transactions | Standard transactions |
|---|---|---|
| `type` | `"0x41"`–`"0x44"` | unchanged |
| `dsaType` | **new**: 4-digit hex identifier, e.g. `"0x0060"` | absent |
| `publicKey` | **new**: hex of the carried public key; absent when nothing is carried | absent |
| `signature` | **new**: hex of the whole signature | absent |
| `v`, `r`, `s`, `yParity` | absent | unchanged |
| `from` | `keccak256(resolved public key)[-20:]` | unchanged |

Example of a `FLEXIBLE_EIP1559` transaction signed with `SECP256K1-MLDSA44` (values shortened):

```json
{
  "accessList": [],
  "blockHash": "0x8d07…",
  "blockNumber": "0x2a",
  "chainId": "0x16bfadfa",
  "dsaType": "0x0060",
  "from": "0x3b7c…",
  "gas": "0xf4240",
  "gasPrice": "0x0",
  "maxFeePerGas": "0x0",
  "maxPriorityFeePerGas": "0x0",
  "hash": "0x9f1c…e27a",
  "input": "0x",
  "nonce": "0x0",
  "to": "0xf17f52151ebef6c7334fad080c5704d77216b732",
  "transactionIndex": "0x0",
  "type": "0x42",
  "value": "0x0",
  "publicKey": "0x…(1312 bytes: the ML-DSA-44 half)…",
  "signature": "0x…(2485 bytes: ECDSA 65 ‖ ML-DSA-44 2420)…"
}
```

- With `dsaType` `0x0001` (secp256k1), `publicKey` is absent and `signature` has 65 bytes.
- **Pending transactions** (`TransactionPendingResult`, used by `txpool_*` methods) report as `publicKey` the **resolved
  full key** (for a hybrid, `pk_ecdsa ‖ pk_pq`) and also include `raw`. Mined transactions report only the carried
  part.

## Code delegation objects

Entries of `authorizationList` (types `0x04` and `0x44`) are returned by `CodeDelegationResult`:

| Field | Flexible delegation | Legacy delegation |
|---|---|---|
| `type` | `"0x1"` | legacy marker |
| `dsaType` | DSA identifier as a **decimal** string, e.g. `"96"` for `0x0060` | — |
| `chainId`, `address`, `nonce` | as usual | as usual |
| `publicKey` | carried key, if any | — |
| `signature` | hex of the signature | hex of the signature |
| `yParity`, `r`, `s` | — | as usual |

> Note: `dsaType` is decimal in delegation objects but hexadecimal in transaction objects.

## Errors

| Situation | Code | Message |
|---|---|---|
| The DSA type is not enabled on the node | `-32602` | `DSA type MLDSA44 (0x0030) is not enabled for accounts on this node` |
| Bad signature, signer cannot be resolved, wrong key length | `-32002` | `Invalid signature` |
| The type is not accepted by the active hard fork (any fork before Prague) | `-32602` family | `Transaction type … is invalid, accepted transaction types are …` |

For security reasons, the "not enabled" error does not list the enabled types. Use `vnt_getAccountsSupportedDSAs`.

## Not supported

- **`eth_sendTransaction`, `eth_call`, `eth_estimateGas`**: their parameter objects have no `dsaType` or `publicKey`.
  Calls behave as in upstream, simulating a standard transaction.
  > ⚠️ **`eth_estimateGas` under-estimates flexible transactions.** It simulates a standard transaction, whose base cost
  > is 21 000, so the estimate is short by the difference between the base cost of the `dsaType` and 21 000 (see
  > [Gas](04-transactions.md#gas)): 65 102 gas for `SECP256K1-MLDSA44`, for instance. A client that uses the estimate as
  > its gas limit gets `intrinsic gas cost … exceeds gas limit` back. Clients that estimate must add
  > `base cost − 21 000` from the table.
- **GraphQL**: no new fields. The schema declares `r` and `s` as non-null, so querying them on a non-ECDSA transaction
  can fail. Use JSON-RPC for flexible transactions.

---

[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Networking](06-networking.md) · [Next: Security considerations →](08-security.md)
