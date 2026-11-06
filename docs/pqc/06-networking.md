[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Consensus](05-consensus.md) · [Next: JSON-RPC API →](07-json-rpc-api.md)

---

# Networking

A node's P2P identity is its public key. In upstream Besu, that is a 64-byte secp256k1 key. In this fork, it is the key
of the node DSA, which for a hybrid node is the 1376-byte `pk_ecdsa ‖ pk_mldsa`. This page describes what that changes
in node IDs, discovery and the transport.

## Contents

- [Overview](#overview)
- [Node IDs and enode URLs](#node-ids-and-enode-urls)
- [Discovery v4 packets](#discovery-v4-packets)
- [Node records (ENR) and the `vnt` identity scheme](#node-records-enr-and-the-vnt-identity-scheme)
- [Discovery v5](#discovery-v5)
- [RLPx transport](#rlpx-transport)
- [The forked discovery library](#the-forked-discovery-library)
- [Falcon node keys](#falcon-node-keys)
- [Interoperability](#interoperability)

## Overview

| Layer | Upstream | This fork, with a `SECP256K1-MLDSA44` node |
|---|---|---|
| Node ID / enode | 64-byte secp256k1 key | 1376-byte hybrid key (2752 hex characters) |
| discv4 packet signature | ECDSA, 65 B | hybrid, 2485 B, plus the 1312-byte ML-DSA key |
| discv4 maximum packet size | 1280 B | 8192 B |
| ENR identity scheme | `v4` (`secp256k1` field) | `vnt` (`secp256k1mldsa44` field) |
| RLPx (ECIES) handshake | secp256k1 ECDH | secp256k1 ECDH using the **ECDSA half** of the node key |

With `SECP256K1` or `SECP256R1` node keys, the wire formats are the same as upstream.

## Node IDs and enode URLs

`EnodeURLImpl` expects node IDs whose length is the public-key length of the **active node DSA**:

```text
enode://<2752 hex characters>@172.20.0.2:30303    ← SECP256K1-MLDSA44
enode://<128 hex characters>@172.20.0.2:30303     ← SECP256K1 / SECP256R1
```

- A 64-byte enode is rejected on a hybrid node, and vice versa. Bootnodes, static nodes and permissioning allowlists
  must therefore use full-length enodes.
- Bootnodes from a built-in network definition that do not parse are ignored with a warning. Bootnodes given on the
  command line fail at start-up.
- A peer's address, as seen by consensus, is `keccak256(nodeId)[-20:]`, which is the same as the validator address.

## Discovery v4 packets

```
upstream:  hash(32) | signature(65)                  | type(1) | RLP data
fork:      hash(32) | signature(sigLen of node DSA)  | (publicKey) | type(1) | RLP data
```

- **Public key.** Only a hybrid node writes a key here, and only its non-recoverable half (e.g. 1312 bytes for
  ML-DSA-44). The receiver recovers the recoverable half from the signature (e.g. the first 65 bytes for ECDSA),
  rebuilds the full node ID and verifies the non-recoverable half. A recoverable node DSA (e.g. `SECP256K1`) writes
  nothing, as upstream. A pure post-quantum node DSA (e.g. `MLDSA44`) writes nothing either, so discovery cannot
  identify the sender (see the [support matrix](05-consensus.md#support-matrix)). The packet hash covers the key bytes.
  See `Packet`, `PacketFactory` and `PacketSerializer` in `ethereum/p2p/.../discovery/discv4/internal/packet/`.
- **Packet size.** `MAX_PACKET_SIZE_BYTES` is raised from 1280 to **8192** bytes (`PeerDiscoveryAgentV4`). Packets larger
  than the path MTU are fragmented at the IP level, which some NATs and firewalls drop. Prefer flat networks or static
  peers for hybrid nodes behind NAT.
- **NEIGHBORS responses.** The number of peers per response is limited by the key size
  (`PeerDiscoveryController.maxNeighborsPerResponse`), so that responses stay within the packet limit.

## Node records (ENR) and the `vnt` identity scheme

[EIP-778](https://eips.ethereum.org/EIPS/eip-778) node records are signed by the node key and name an *identity scheme*.
The fork adds the scheme **`vnt`**:

| Node key | Scheme | Key field | Signature |
|---|---|---|---|
| ECDSA | `v4` | `secp256k1` (compressed key) | 64 B (`r ‖ s`) |
| Hybrid `SECP256K1-MLDSA44` | `vnt` | `secp256k1mldsa44` (full 1376-byte key) | full hybrid signature (2485 B) |

- `NodeRecordManager` signs the record with the node DSA (`nodeKey.sign(keccak256(record), "node-record")`).
- `EnrSignatureValidator` verifies it: it recovers the ECDSA half, verifies the ML-DSA half, and checks that the record
  belongs to the node ID of the sender.

## Discovery v5

> ⚠️ **Discovery v5 is not recommended with this fork.** Its messages are not signed with the node DSA.

Discovery v5 can decode and verify `vnt` records (`VerifyingVntInterpreter`, `BootnodeRecordFactory`), but the discv5
session handshake still signs with the **ECDSA half** of the node key (`LocalNodeKeySigner`). A hybrid node is
therefore authenticated only classically on discv5. Use discovery v4 or static peers instead. Discovery v5 is
experimental in upstream Besu as well.

## RLPx transport

The RLPx (ECIES) handshake that establishes encrypted peer sessions is unchanged in principle. It uses the secp256k1 half
of the node key (`PublicKeyHandler.secp256k1`, `EnodeURLImpl.secp256k1PublicKey`) for ECDH.

- Pure ML-DSA or Falcon node keys cannot complete the handshake (`Besu only supports ECDH with SECP private key`).
- Session keys are established with classical ECDHE. Replacing it with a post-quantum KEM is outside the scope
  of this fork (see [Security considerations](08-security.md#out-of-scope-and-limitations)).
- Post-quantum *authentication* of a peer's identity comes from discovery (signed packets and records) and from
  consensus (every consensus message is signed). The RLPx handshake itself authenticates only the ECDSA half.

## The forked discovery library

Besu uses the `tech.pegasys.discovery` library for node records and discv5. The fork depends on a fork of it,
[venturusbr/discovery-besu-ppi](https://github.com/venturusbr/discovery-besu-ppi) (branch `development`). It is upstream
26.1.0 plus:

- the `vnt` identity scheme (`IdentitySchema.VNT`, `IdentitySchemaVntInterpreter`), which supports records up to 7500
  bytes;
- a maximum packet size of 8192 bytes.

Gradle resolves it as a **source dependency**, cloning and building it from Git (`settings.gradle`, `sourceControl {
gitRepository(...) }`). The build therefore needs access to that repository. To build against a local checkout instead,
pass `-PdiscoveryPath=/path/to/discovery-besu-ppi`.

## Falcon node keys

`SECP256K1-FALCON512` is **experimental as a node DSA**. Consensus works, but peer discovery does not:

- discv4 assumes a fixed signature length to find the public key in a packet. Falcon signatures vary in length, so
  decoding fails.
- Node records have no Falcon field. The `vnt` scheme and its validator are specific to `SECP256K1-MLDSA44`.

Workaround, used by [besu-qbft](11-usage/running-a-network.md#falcon-node-keys-experimental): disable discovery and
connect the nodes with static peers.

```toml
discovery-enabled=false
static-nodes-file="/usr/app/static-nodes.json"
```

Falcon is fully supported as an **account** DSA, whatever the node DSA.

## Interoperability

- A network of `SECP256K1` or `SECP256R1` nodes is wire-compatible with upstream Besu and other Ethereum clients.
- Hybrid nodes can only peer with other hybrid nodes of this fork that use the same node DSA. Their enodes, discovery
  packets and records are not understood by standard clients.

---

[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Consensus](05-consensus.md) · [Next: JSON-RPC API →](07-json-rpc-api.md)
