[🏠 Index](README.md) · **⚡ Quick start** · [← Previous: Index](README.md) · [Next: Motivation and design →](01-motivation-and-design.md)

---

# ⚡ Quick start

Skip the theory: build the node, start a four-validator QBFT network, and send one post-quantum
signed transaction. Expect about 15 minutes, most of it spent on the first Gradle build.

> The explanations behind each step are in the rest of the documentation. Start with
> [Running a network](11-usage/running-a-network.md) and
> [Sending transactions](11-usage/sending-transactions.md) when you want more than the minimal test.

## Contents

- [Prerequisites](#prerequisites)
- [1. Build the Besu PQC Docker image](#1-build-the-besu-pqc-docker-image)
- [2. Get the companion projects](#2-get-the-companion-projects)
- [Minimal test](#minimal-test)
- [Troubleshooting](#troubleshooting)
- [Where to go next](#where-to-go-next)

## Prerequisites

| Tool | Version | Used for |
|---|---|---|
| Java (JDK) | 21 or later | building Besu and the wallet |
| Docker with Compose v2 (`docker compose`) | recent | running the network |
| Maven | 3.x | building the wallet |
| Git and a Bash shell | — | cloning and running the network script |

The network script is a Bash script. It runs on Linux and macOS. On Windows, use WSL 2 (recommended) or Git Bash with
Docker Desktop or Rancher Desktop.

## 1. Build the Besu PQC Docker image

```bash
git clone https://github.com/venturusbr/besu-pqc-ppi.git
```

```bash
cd besu-pqc-ppi
```

```bash
./gradlew -Pversion=26.1.0-pqc -Prelease.releaseVersion=26.1.0-pqc distDocker
```

This builds the distribution and the image `hyperledger/besu:26.1.0-pqc`, the default image name the network scripts
expect. Check that it exists:

```bash
docker images hyperledger/besu
```

> On Windows, run the Gradle command from WSL or Git Bash. Either way, the `distDocker` task calls `bash` through WSL,
> so WSL must be installed. See [Installation](09-installation.md#building-the-docker-image) for building the image by
> hand without WSL.

## 2. Get the companion projects

```bash
git clone https://github.com/venturusbr/besu-qbft.git
```

```bash
git clone https://github.com/venturusbr/besu-flex-wallet-ppi.git
```

Build the wallet once:

```bash
cd besu-flex-wallet-ppi && mvn clean install
```

## Minimal test

This minimal test confirms that the network starts correctly and that the wallet can submit a single transaction.

### 1. Start the QBFT network

In a first terminal:

```bash
cd besu-qbft && chmod +x init-qbft.sh
```

```bash
./init-qbft.sh hyperledger/besu:26.1.0-pqc
```

The script generates a fresh genesis and keys for four validators, then starts them with `docker compose` in the
foreground and streams every node's log. Its first output lines look like this:

```text
Using image hyperledger/besu:26.1.0-pqc with node DSA SECP256K1 (ecCurve secp256k1)
...
Created 4 nodes
```

> To run the validators themselves with hybrid post-quantum keys, add `--node-dsa=SECP256K1-MLDSA44`. The minimal test
> works the same way with that option.

### 2. Wait until blocks are being produced

Each node logs the DSAs that accounts may sign with:

```text
node-1  | ... | INFO  | DigitalSignatureAlgorithmConfiguration | Account-enabled DSAs: SECP256K1, SECP256R1, SECP256K1-MLDSA44, SECP256K1-FALCON512
```

Then, every 2 seconds, one validator produces a block and the others import it:

```text
node-2  | ... | INFO  | QbftBesuControllerBuilder | Produced empty block #3 / 0 tx / 0 pending / 0 (0.0%) gas / (0x5c1e...)
node-1  | ... | INFO  | QbftBesuControllerBuilder | Imported empty block #3 / 0 tx / 0 pending / 0 (0.0%) gas / (0x5c1e...)
```

When the block number keeps increasing, the network is ready.

### 3. In a second terminal, send a single transaction using the flex-wallet

```bash
cd besu-flex-wallet-ppi
```

```bash
mvn exec:java -Dexec.args="--generateKeys --txType FlexibleEIP1559"
```

This command does three things:
- It generates a fresh hybrid **ECDSA secp256k1 + ML-DSA-44** key pair, stored in `~/.besu-flex-wallet/keys.txt`.
- It signs a `FlexibleEIP1559` transaction (type `0x42`) with that key.
- It sends the transaction to `http://localhost:8545` with `eth_sendRawTransaction`.

The last line printed is the JSON-RPC response with the transaction hash:

```text
Hybrid DSA: SECP256K1-MLDSA44 (dsaType 0x0060)
...
Result: {"jsonrpc":"2.0","id":1,"result":"0x9f1c...e27a"}
```

> - **PowerShell:** quote the whole property instead: `mvn exec:java "-Dexec.args=--generateKeys --txType FlexibleEIP1559"`.
> - **Falcon:** to sign with the hybrid ECDSA + Falcon-512 instead, add `--hybridDsa SECP256K1-FALCON512`.

### 4. What to look for in the QBFT network log

Back in the first terminal, within one block period (2 s) the block counter shows a block with **1 tx**:

```text
node-3  | ... | INFO  | QbftBesuControllerBuilder | Produced block #42 / 1 tx / 0 pending / 86,102 (0.0%) gas / (0x8d07...)
node-1  | ... | INFO  | QbftBesuControllerBuilder | Imported block #42 / 1 tx / 0 pending / 86,102 (0.0%) gas / (0x8d07...)
```

Besu does not log transactions at `INFO` level when they enter the transaction pool. The `1 tx` block is the signal
that the hybrid signature was accepted by the pool, included by the proposer, and verified again by every validator
that imported the block.

To confirm from the second terminal, query the transaction by the hash the wallet printed. The response includes the
fork's `dsaType` and `publicKey` fields:

```bash
curl -s -X POST -H "Content-Type: application/json" --data '{"jsonrpc":"2.0","method":"eth_getTransactionByHash","params":["0x<hash>"],"id":1}' http://localhost:8545
```

### 5. Stop the network by pressing Ctrl+C in the first terminal

`Ctrl+C` stops the containers. To also remove the containers and the Docker network:

```bash
docker compose -f docker-compose.generated.yaml down
```

Every run of `init-qbft.sh` starts a new chain from block 0, with new keys.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Genesis generation failed: see the genesis-generator output above` | The image name is wrong or the image was not built. Check `docker images hyperledger/besu`. |
| The wallet prints a `Connection refused` stack trace | The network is not up yet, or node 1 is not listening on port 8545. Wait for the block logs. |
| The wallet's response contains an error about the nonce | Single-transaction mode always uses nonce 0. Reusing a key on the same chain fails, so pass `--generateKeys`. |
| The wallet refuses the key file | The stored key is for another scheme or curve. Pass `--generateKeys`. |
| `Missing PKEY_SECP256K1 field` in the logs of a `SECP256R1` network | Harmless. The discovery library looks for a secp256k1 key in node records first. |

## Where to go next

- [Running a network](11-usage/running-a-network.md): every node DSA, network sizes and alternatives.
- [Sending transactions](11-usage/sending-transactions.md): batch mode, Falcon, plain EIP-1559 for comparison.
- [Transactions](04-transactions.md): what a flexible transaction looks like on the wire.
- [Motivation and design](01-motivation-and-design.md): why the fork exists.

---

[🏠 Index](README.md) · **⚡ Quick start** · [← Previous: Index](README.md) · [Next: Motivation and design →](01-motivation-and-design.md)
