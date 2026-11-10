[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Installation](09-installation.md) · [Next: Usage →](11-usage/README.md)

---

# Configuration

The fork adds two command-line options and one subcommand option. Everything else is configured as in
[upstream Besu](https://besu.hyperledger.org).

## Contents

- [Options reference](#options-reference)
- [Genesis `ecCurve` and node DSA](#genesis-eccurve-and-node-dsa)
- [Hard fork](#hard-fork)
- [Example `config.toml`](#example-configtoml)
- [Generating a network](#generating-a-network)
- [Compatibility matrix](#compatibility-matrix)
- [Start-up errors](#start-up-errors)

## Options reference

### `--node-dsa`

| | |
|---|---|
| Syntax | `--node-dsa=<NAME>` |
| Config file | `node-dsa="SECP256K1-MLDSA44"` |
| Environment | `BESU_NODE_DSA` |
| Default | the algorithm of the genesis `ecCurve`: `SECP256K1`, or `SECP256R1` when `ecCurve` is `secp256r1` |
| Values | `SECP256K1`, `SECP256R1`, `SECP256K1-MLDSA44`, `SECP256K1-FALCON512` (experimental), `MLDSA44`, `MLDSA65`, `MLDSA87`, `FALCON512` (not usable with P2P) |

The algorithm of the node's own key, used for consensus messages, block seals, discovery and node records. Names are
case-sensitive. With a non-ECDSA node DSA, also pass **`--node-private-key-file`**: the key is not generated
automatically (see [Key management](03-cryptography/key-management.md#node-keys-at-start-up)).

### `--accounts-supported-dsas`

| | |
|---|---|
| Syntax | `--accounts-supported-dsas=<NAME>[,<NAME>...]` |
| Config file | `accounts-supported-dsas=["SECP256K1","SECP256K1-MLDSA44"]` |
| Environment | `BESU_ACCOUNTS_SUPPORTED_DSAS` |
| Default | `SECP256K1` |
| Values | any name in [the algorithm registry](03-cryptography/algorithms.md#identifiers-and-sizes); case-insensitive |

The algorithms that transactions and code delegations may use. Transactions with any other `dsaType` are rejected (see
[Validation](04-transactions.md#validation)). Standard (non-flexible) transactions and legacy code delegations are
signed with the network curve, so they are rejected too when that curve (`SECP256K1`, or `SECP256R1` on a `secp256r1`
network) is left out. The node logs the list at start-up:

```text
Account-enabled DSAs: SECP256K1, SECP256R1, SECP256K1-MLDSA44, SECP256K1-FALCON512
```

### `--rpc-http-api` / `--rpc-ws-api`

Add `VNT` to expose [`vnt_getAccountsSupportedDSAs`](07-json-rpc-api.md#vnt_getaccountssupporteddsas).

### `besu operator generate-blockchain-config --node-dsa`

Generates node keys and the genesis validators with the given DSA. The default and the curve check are the same as for
the main option. See [Generating a network](#generating-a-network).

## Genesis `ecCurve` and node DSA

The genesis `config.ecCurve` (`secp256k1` by default, or `secp256r1`) selects the elliptic curve of the network. Besu
refuses to start when `--node-dsa` signs on another curve:

| `ecCurve` | Allowed `--node-dsa` |
|---|---|
| `secp256k1` (default) | `SECP256K1`, `SECP256K1-MLDSA44`, `SECP256K1-FALCON512`, pure post-quantum |
| `secp256r1` | `SECP256R1`, pure post-quantum. **Hybrids are not available** (both hybrids use secp256k1) |

On a `secp256r1` network, standard transactions are signed on secp256r1 too. Account DSAs are independent of the curve,
so a secp256r1 network can still accept `SECP256K1-MLDSA44` flexible transactions if they are enabled.

## Hard fork

Flexible transactions are accepted from **Prague** onwards, including Osaka, the BPO forks and Amsterdam (see
[Transactions → Hard-fork activation](04-transactions.md#hard-fork-activation)). A suitable genesis `config` section:

```json
{
  "config": {
    "chainId": 381660666,
    "pragueTime": 0,
    "zeroBaseFee": true,
    "qbft": { "blockperiodseconds": 2, "epochlength": 30000, "requesttimeoutseconds": 10 }
  }
}
```

## Example `config.toml`

A QBFT validator with a hybrid node key that accepts every account DSA (adapted from
[besu-qbft](https://github.com/venturusbr/besu-qbft)):

```toml
data-path="/usr/app/data"
genesis-file="/usr/app/genesis.json"

# Node key
node-dsa="SECP256K1-MLDSA44"
node-private-key-file="/usr/app/data/key"

# Account DSAs
accounts-supported-dsas=["SECP256K1", "SECP256R1", "SECP256K1-MLDSA44", "SECP256K1-FALCON512"]

# RPC
rpc-http-enabled=true
rpc-http-api=["ETH","NET","QBFT","VNT"]
rpc-http-port=8545
host-allowlist=["*"]
rpc-http-cors-origins=["all"]

# P2P: enodes are full-length (2752 hex characters for SECP256K1-MLDSA44)
p2p-host="172.20.0.2"
p2p-port=30303
bootnodes=["enode://<2752 hex chars>@172.20.0.2:30303"]

# Transaction pool and gas
tx-pool="sequenced"
tx-pool-max-size=10000
min-gas-price=0

metrics-enabled=true
metrics-host="0.0.0.0"
metrics-port=9545
```

## Generating a network

```bash
besu operator generate-blockchain-config --config-file=qbftConfig.json --to=networkFiles --private-key-file-name=key --node-dsa=SECP256K1-MLDSA44
```

`qbftConfig.json` follows the upstream format (`genesis` plus `blockchain.nodes.count`). Add `"ecCurve"` to the genesis
`config` for secp256r1 networks. The output is described in
[Key management → Generating node keys](03-cryptography/key-management.md#generating-node-keys). Then, for each node:

1. copy `genesis.json` and the node's `key` into its data directory;
2. set `node-dsa` and `node-private-key-file`;
3. point `bootnodes` (or `static-nodes.json`) at full-length enodes, built from each `key.pub`:
   `enode://<key.pub without 0x>@<host>:<port>`.

[besu-qbft](11-usage/running-a-network.md) automates all of this.

## Compatibility matrix

| | QBFT / IBFT 2.0 | Clique | Discovery | Standard Ethereum peers |
|---|---|---|---|---|
| `--node-dsa=SECP256K1` | ✓ | ✓ | ✓ discv4 / discv5 | ✓ |
| `--node-dsa=SECP256R1` + `ecCurve: secp256r1` | ✓ | ✓ | ✓ (harmless `Missing PKEY_SECP256K1 field` log) | — |
| `--node-dsa=SECP256K1-MLDSA44` | ✓ | ✓ | ✓ (`vnt` ENR, 8 KB packets) | — |
| `--node-dsa=SECP256K1-FALCON512` | ✓ | ✓ | ✗ (static nodes only) | — |

| Account DSA | Transaction types |
|---|---|
| network curve (`SECP256K1` or `SECP256R1`) | standard `0x00`–`0x04` and flexible `0x41`–`0x44` with that `dsaType`, if it is enabled |
| any other enabled DSA | flexible `0x41`–`0x44` only |

All nodes of a network must share the same `--node-dsa` and the same `--accounts-supported-dsas`.

## Start-up errors

| Message (abridged) | Cause |
|---|---|
| `--node-dsa X signs on the secp256k1 curve, but …` | `--node-dsa` does not match the genesis `ecCurve` |
| `--node-dsa X pairs its post-quantum half with secp256k1, but … Hybrid algorithms are only available with secp256k1 for now` | a hybrid on a secp256r1 network |
| `Algorithm name provided is not supported` | unknown `--node-dsa` name (names are case-sensitive) |
| `Unsupported DSA algorithm: X` | unknown name in `--accounts-supported-dsas` |
| `Invalid enode URL syntax …` / wrong node ID length | an enode whose key length does not match the node DSA |

---

[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Installation](09-installation.md) · [Next: Usage →](11-usage/README.md)
