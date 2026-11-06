[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Transactions](04-transactions.md) · [Next: Networking →](06-networking.md)

---

# Consensus

Proof-of-authority consensus protocols sign everything with the validators' **node keys**: BFT messages
(proposal, prepare, commit, round change), commit seals in block headers, and Clique proposer seals. Upstream identifies
the signer by recovering its ECDSA key. With a non-recoverable node DSA (ML-DSA, Falcon or a hybrid), the signer's
public key must travel with the signature and the signature must be verified explicitly.

## Contents

- [Support matrix](#support-matrix)
- [Common rule](#common-rule)
- [BFT messages (QBFT and IBFT 2.0)](#bft-messages-qbft-and-ibft-20)
- [Commit seals in the block header](#commit-seals-in-the-block-header)
- [Clique](#clique)
- [Validators and genesis](#validators-and-genesis)
- [Signature checks during block processing](#signature-checks-during-block-processing)
- [Network-wide requirements](#network-wide-requirements)
- [Tests](#tests)

## Support matrix

| Node DSA | QBFT | IBFT 2.0 | Clique | IBFT 1.0 (legacy) | Usable on a real network |
|---|---|---|---|---|---|
| `SECP256K1` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `SECP256R1` | ✓ | ✓ | ✓ | ✗ | ✓ (`ecCurve: secp256r1`) |
| `SECP256K1-MLDSA44` | ✓ | ✓ | ✓ | ✗ | ✓ |
| `SECP256K1-FALCON512` | ✓ | ✓ | ✓ | ✗ | ⚠ experimental: static peers, discovery off ([why](06-networking.md#falcon-node-keys)) |
| `MLDSA44`, `FALCON512` | ✓ (tests) | ✓ (tests) | ✓ (tests) | ✗ | ✗ (no RLPx key agreement, see [Key management](03-cryptography/key-management.md#key-agreement-ecdh)) |

The consensus layer itself is algorithm-agnostic: `MLDSA65` and `MLDSA87` use the same code paths, although the
consensus tests do not cover them. In this table, "tests" means consensus tests with mocked peers.

## Common rule

For every signed consensus object, the fork:

1. writes the signature as an opaque byte string, of any length;
2. writes the signer's public key **only if the node DSA cannot recover it**. For a hybrid, only the post-quantum half
   is written, following [the public-key encoding rules](03-cryptography/key-management.md#public-key-encoding-rules);
3. on receipt, resolves the key (recovering what can be recovered), **verifies** the signature if the DSA is not
   recoverable, and derives the author as `keccak256(publicKey)[-20:]`.

With `SECP256K1` or `SECP256R1`, nothing extra is written, and all encodings are **byte-identical to upstream**.

## BFT messages (QBFT and IBFT 2.0)

```
SignedData = RLP[ payload, signature, (publicKey) ]
```

- **Encoding.** `SignedData.writeTo` writes the message. QBFT reads it in `BftMessage` and IBFT 2.0 in
  `PayloadDeserializers`. Nested messages (round-change certificates, prepared certificates) use the same encoding.
- **Verification on decode.** `SignedData.create` resolves the key, verifies the signature for non-recoverable DSAs
  (failure: `Signature verification failed`), checks malleability for ECDSA, and caches the author.
- **Locally signed messages.** Messages the node signs itself are built with `createLocallySigned`, which skips
  self-verification. The message factories attach the node's key when the DSA requires it.
- **Decode once.** Each message is now decoded and verified once. The gossiper reuses the author from the decoded
  `SignedData` instead of decoding the message again, which matters when verification costs milliseconds.

## Commit seals in the block header

QBFT and IBFT 2.0 store the validators' commit seals in the block header `extraData`:

```
QBFT extraData = RLP[ vanity, [validators], vote, round, seals ]
seals (recoverable DSA)      = [ seal₁, seal₂, … ]
seals (non-recoverable DSA)  = [ seal₁, key₁, seal₂, key₂, … ]
```

- `CommitSeal` pairs a seal with its optional public key. `BftExtraDataCodec` writes each key immediately after its seal,
  in the same flat list.
- A hybrid uses the non-recoverable layout, but `keyᵢ` holds only the part of the key that cannot be recovered: the half
  of a non-recoverable algorithm when the other half is recoverable, or the whole key when neither is. The recoverable
  half is recovered from the seal when it is decoded.
- Seals are not covered by the block hash (`encodeWithoutCommitSeals`), so carrying keys does not change block hashes.
- `CommitSeal.recoverVerifiedAuthor` verifies each seal against its key. A seal that fails is **discarded** with
  `Discarding commit seal that failed verification against its supplied public key.`, and the block is valid only if
  enough valid seals remain to reach quorum (`BftCommitSealsValidationRule`).
- When building a block, each commit seal is paired with the key of the commit message that carried it
  (`RoundState.getCommitSeals`).

## Clique

Clique stores the proposer's seal at the end of `extraData`. For non-recoverable DSAs, `CliqueExtraData` uses a layout
with the key and a footer that records the lengths:

```
recoverable DSA:      vanity(32) | validators(20·n) | seal(65)
non-recoverable DSA:  vanity(32) | validators(20·n) | key(K) | seal(S) | K(2) | S(2)
```

- `K` and `S` are 2-byte big-endian unsigned lengths. For a hybrid, `key` is only the post-quantum half.
- The seal signs `vanity | validators | key | K`, so the carried key cannot be swapped.
- The decoder rejects inconsistent lengths, validator bytes that are not a multiple of 20, a missing key, and keys of
  the wrong length.
- **Genesis compatibility:** under a non-recoverable DSA, the genesis block may still use the classic layout with an
  all-zero seal, so existing Clique genesis files keep working. Every later block uses the new layout.
- The proposer is attributed in `CliqueBlockHashing`: resolve the key, verify the seal, then derive the address. On
  failure: `Proposer seal does not verify against the public key the header carries`.

## Validators and genesis

- A validator's address is `Address.extract(nodePublicKey)`. For a hybrid, it is the hash of the **full** 1376-byte
  (ML-DSA) or 960-byte (Falcon) key.
- `besu operator generate-blockchain-config --node-dsa=<DSA>` generates the node keys and writes their addresses into
  the genesis `extraData` (see [Key management](03-cryptography/key-management.md#generating-node-keys)).
- The genesis `ecCurve` decides which ECDSA curve the network uses. `--node-dsa` must sign on that curve, which means
  that hybrids require `secp256k1` (see [Configuration](10-configuration.md#genesis-eccurve-and-node-dsa)).
- Adding and removing validators through votes (`qbft_proposeValidatorVote` and so on) works with addresses, as in
  upstream. QBFT validator-contract mode has not been tested with post-quantum DSAs.

## Signature checks during block processing

Consensus authenticates the *proposer* and the *committers*. It does not authenticate each transaction. The fork
therefore also re-verifies transaction signatures while processing every block (see
[Transactions → Validation](04-transactions.md#where-transaction-signatures-are-checked)). Successful verifications are
cached by transaction hash, so a validator that already verified a transaction at pool admission does not pay for it
again during proposal validation or block import.

## Network-wide requirements

> ⚠️ **Every node of a network must use the same `--node-dsa`, chosen when the network is created and kept for the
> life of the chain.** The format of consensus messages, commit seals and `extraData` follows the node DSA, and there is
> no hard-fork activation to switch algorithms on a running chain. A node with a different DSA cannot decode its peers'
> messages, and its peers reject its identity, because its discovery packets and node record (ENR) use a different
> format. Enode URLs configured with a key of the wrong length (bootnodes, static nodes, allowlists) are also rejected
> when the configuration is parsed (see [Networking](06-networking.md)).

## Tests

| What | Where | How to run |
|---|---|---|
| QBFT and IBFT 2.0 integration tests, run under every DSA | `consensus/qbft-core/src/integration-test`, `consensus/ibft/src/integration-test`, `gradle/consensus-dsa-integration-tests.gradle` | `./gradlew :consensus:qbft-core:integrationTestPqc` |
| Clique with non-recoverable DSAs | `CliqueExtraDataNonRecoverableTest`, `CliqueBlockCreatorNonRecoverableTest` | `./gradlew :consensus:clique:test` |

See [Testing and compatibility](13-testing.md) for all the tasks.

---

[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Transactions](04-transactions.md) · [Next: Networking →](06-networking.md)
