[🏠 Index](../README.md) · [⚡ Quick start](../00-quick-start.md) · [↑ Usage](README.md) · [← Previous: Running a network](running-a-network.md) · [Next: Metrics and performance →](../12-metrics-and-performance.md)

---

# Sending transactions

## Contents

- [The flex wallet](#the-flex-wallet)
- [Build](#build)
- [Options](#options)
- [Examples](#examples)
- [Single-transaction mode](#single-transaction-mode)
- [Batch mode](#batch-mode)
- [Checking results](#checking-results)
- [Transaction types at a glance](#transaction-types-at-a-glance)
- [Other clients](#other-clients)

## The flex wallet

[besu-flex-wallet-ppi](https://github.com/venturusbr/besu-flex-wallet-ppi) is a small Java command-line wallet. It can
build two kinds of transactions:

| `--txType` | Wire type | Signature | Works on |
|---|---|---|---|
| `FlexibleEIP1559` | `0x42` | hybrid `SECP256K1-MLDSA44` (default) or `SECP256K1-FALCON512` | this fork only |
| `EIP1559` | `0x02` | ECDSA on secp256k1 (default) or secp256r1 | this fork and standard Besu, for comparison |

The wallet signs a fixed transfer on the [besu-qbft](running-a-network.md) network:

| Field | Value |
|---|---|
| chain ID | 381660666 |
| to | `0xf17f52151EbEF6C7334FAD080c5704D77216b732` |
| value, data | 0, empty |
| gas limit | 1 000 000 |
| max fee, max priority fee | 0 |

These transactions need no funds on a network where gas is free. To use the wallet on another network, change these
values in the source.

## Build

Requires Java 21 and Maven 3.

```bash
cd besu-flex-wallet-ppi && mvn clean install
```

Run it with `mvn exec:java -Dexec.args="…"`. In PowerShell, quote the whole property:
`mvn exec:java "-Dexec.args=--txType FlexibleEIP1559"`.

## Options

Flags are case-insensitive and accept `--flag value` or `--flag=value`.

| Flag | Values | Default | Description |
|---|---|---|---|
| `--txType` | `FlexibleEIP1559`, `EIP1559` | **required** | Transaction type to build |
| `--hybridDsa` | `SECP256K1-MLDSA44`, `SECP256K1-FALCON512` | `SECP256K1-MLDSA44` | Hybrid algorithm for `FlexibleEIP1559` |
| `--ecCurve` | `secp256k1`, `secp256r1` | `secp256k1` | Curve for `EIP1559`. Use `secp256r1` on a `--node-dsa=SECP256R1` network |
| `--txAmount` | integer ≥ 1 | — | Enables batch mode with N transactions |
| `--nodes` | comma-separated URLs | `http://localhost:8545` (single), `…:8545`–`…:8548` (batch) | JSON-RPC endpoints |
| `--maxRate` | transactions per second (decimal) | unlimited | Batch submission rate limit |
| `--output` | path | `tx_results_<yyyyMMdd-HHmmss>.csv` | Batch CSV report |
| `--generateKeys` | — | — | Generate a new key pair in single mode, overwriting the stored one |
| `--help`, `-h` | — | — | Print usage |

## Examples

**One hybrid ML-DSA transaction** (the [minimal test](../00-quick-start.md#minimal-test)):

```bash
mvn exec:java -Dexec.args="--generateKeys --txType FlexibleEIP1559"
```

**One hybrid Falcon transaction:**

```bash
mvn exec:java -Dexec.args="--generateKeys --txType FlexibleEIP1559 --hybridDsa SECP256K1-FALCON512"
```

**One standard EIP-1559 transaction**, for comparison:

```bash
mvn exec:java -Dexec.args="--generateKeys --txType EIP1559"
```

**A standard EIP-1559 transaction on a secp256r1 network** (`./init-qbft.sh … --node-dsa=SECP256R1`):

```bash
mvn exec:java -Dexec.args="--generateKeys --txType EIP1559 --ecCurve secp256r1"
```

**A batch of 1000 hybrid transactions across four nodes**, at most 100 tx/s:

```bash
mvn exec:java -Dexec.args="--txAmount 1000 --txType FlexibleEIP1559 --maxRate 100"
```

**A batch sent to selected nodes, with a named report:**

```bash
mvn exec:java -Dexec.args="--txAmount 200 --txType FlexibleEIP1559 --hybridDsa SECP256K1-FALCON512 --nodes http://localhost:8545,http://localhost:8546 --output falcon.csv"
```

## Single-transaction mode

Without `--txAmount`, the wallet signs **one** transaction with **nonce 0** using the key pair stored in
`~/.besu-flex-wallet/keys.txt`, and sends it to the first endpoint.

- The key file is created if it is missing, or replaced when `--generateKeys` is passed. Hybrid keys are stored as
  PEM-like Base64 sections (`PUBLIC KEY`, `PRIVATE KEY`, `SECOND PUBLIC KEY`, `SECOND PRIVATE KEY`).
- The wallet refuses a key file whose algorithm or curve does not match the options. Pass `--generateKeys`.
- Nonce 0 can be used only once per account and chain. Pass `--generateKeys` to send another single transaction on the
  same chain.

Output for a hybrid transaction:

```text
Hybrid DSA: SECP256K1-MLDSA44 (dsaType 0x0060)
Generated new keys. File Path: /home/user/.besu-flex-wallet/keys.txt
~~~ Public key length ~~~
1312
~~~ Secret key length ~~~
…
~~~ Signature length ~~~
…
Result: {"jsonrpc":"2.0","id":1,"result":"0x9f1c…e27a"}
```

The `Result` line is the raw `eth_sendRawTransaction` response: a transaction hash, or a JSON-RPC error (see
[JSON-RPC API → Errors](../07-json-rpc-api.md#errors)).

## Batch mode

With `--txAmount N`, the wallet generates **N fresh accounts in memory** and signs one transaction per account. Each
transaction uses nonce 0, so all of them are independent. It sends them in parallel (16 workers) to the endpoints in
round-robin order, honouring `--maxRate`.

Progress line:

```text
[ 42.0%] 420/1000  ok=420 fail=0  rate=99.8 tx/s  elapsed=00:00:04  eta=00:00:05
```

Summary:

```text
================ Transaction Batch Summary ================
Total:      1000
Succeeded:  1000
Failed:     0
Elapsed:    00:00:10
Rate:       99.87 tx/s
Per-endpoint:
  - http://localhost:8545  ok=250 fail=0 total=250
  …
CSV: /home/user/besu-flex-wallet-ppi/tx_results_20261028-123306.csv
```

CSV columns (`nonce` is the transaction index):

```text
nonce,endpoint,status,txHash,errorMessage,elapsedMs,timestamp
0,http://localhost:8545,success,0x308b…,,1575,2026-10-28T12:33:06.572999400Z
```

Without `--maxRate`, the wallet can submit faster than consensus includes transactions and fill the pools. Choose a rate
that matches the block period and the gas limit.

## Checking results

In the network log, a block with transactions:

```text
node-3  | … | QbftBesuControllerBuilder | Produced block #42 / 1 tx / 0 pending / 86,102 (0.0%) gas / (0x8d07…)
```

Over JSON-RPC:

```bash
curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0x<hash>"],"id":1}' http://localhost:8545
```

```bash
curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionReceipt","params":["0x<hash>"],"id":1}' http://localhost:8545
```

A flexible transaction shows `"type":"0x42"`, `"dsaType":"0x0060"` (or `"0x0070"` for Falcon), the carried `publicKey`
and the `signature` (see [Transaction objects](../07-json-rpc-api.md#transaction-objects)).

## Transaction types at a glance

| Transaction | Type | How to send it |
|---|---|---|
| Legacy, access list, EIP-1559, blob, set-code (ECDSA) | `0x00`–`0x04` | any Ethereum tool, signed with the network curve |
| Flexible EIP-1559 with a hybrid DSA | `0x42` | flex wallet, `--txType FlexibleEIP1559` |
| Flexible access list | `0x41` | Java API (`Transaction.Builder`), see [Transactions](../04-transactions.md#building-and-signing-transactions-in-java) |
| Flexible blob | `0x43` | Java API |
| Flexible set-code, with legacy and/or flexible delegations | `0x44` | Java API (`CodeDelegation.Builder`) |
| Flexible with a pure ML-DSA-44/65/87 or Falcon-512 key | `0x41`–`0x44` | Java API. Enable the DSA in `accounts-supported-dsas` first |

## Other clients

Any client can send flexible transactions if it:

1. builds the RLP field list for the type ([Wire encoding](../04-transactions.md#wire-encoding));
2. signs `keccak256(type ‖ rlp([dsaType, …, (publicKey)]))` with the chosen DSA
   ([Signing hash](../04-transactions.md#signing-hash));
3. appends the signature and calls `eth_sendRawTransaction`.

The flex wallet source is a reference implementation, and `vnt_getAccountsSupportedDSAs` tells a client which DSAs a node
accepts.

---

[🏠 Index](../README.md) · [⚡ Quick start](../00-quick-start.md) · [↑ Usage](README.md) · [← Previous: Running a network](running-a-network.md) · [Next: Metrics and performance →](../12-metrics-and-performance.md)
