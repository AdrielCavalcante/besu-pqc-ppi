[🏠 Index](../README.md) · [⚡ Quick start](../00-quick-start.md) · [↑ Cryptography](README.md) · [← Previous: Cryptography](README.md) · [Next: Hybrid signatures →](hybrid-signatures.md)

---

# Algorithms

## Contents

- [Identifiers and sizes](#identifiers-and-sizes)
- [ECDSA: SECP256K1 and SECP256R1](#ecdsa-secp256k1-and-secp256r1)
- [ML-DSA](#ml-dsa)
- [Falcon-512](#falcon-512)
- [Hybrids](#hybrids)
- [Where each algorithm can be used](#where-each-algorithm-can-be-used)
- [Adding an algorithm](#adding-an-algorithm)

## Identifiers and sizes

Every DSA is a constant of `DSAParametersSet`
(`crypto/algorithms/.../algorithms/parameters/DSAParametersSet.java`). The 2-byte identifier is what goes on the wire
(the `dsaType` field), and the name is what the CLI options use.

| Name | ID | Private key (B) | Seed (B) | Public key (B) | Signature (B) | Supports PKR | Standard |
|---|---|---|---|---|---|---|---|
| `SECP256K1` | `0x0001` | 32 | — | 64 | 65 | ✓ | SEC 2 (Ethereum default) |
| `SECP256R1` | `0x0002` | 32 | — | 64 | 65 | ✓ | NIST P-256 |
| `MLDSA44` | `0x0030` | 2560 | 32 | 1312 | 2420 | ✗ | FIPS 204, category 2 |
| `MLDSA65` | `0x0031` | 4032 | 32 | 1952 | 3309 | ✗ | FIPS 204, category 3 |
| `MLDSA87` | `0x0032` | 4896 | 32 | 2592 | 4627 | ✗ | FIPS 204, category 5 |
| `FALCON512` | `0x0040` | 2176 | — | 896 | variable, ≤ 752 | ✗ (see note) | Falcon round 3 (FN-DSA), category 1 |
| `SECP256K1-MLDSA44` | `0x0060` | 2592 | — | 1376 | 2485 | ECDSA half only | hybrid |
| `SECP256K1-FALCON512` | `0x0070` | 2208 | — | 960 | 65 + variable | ECDSA half only | hybrid |

**Seed**: ML-DSA private keys can also be given as a 32-byte seed (FIPS 204 ξ), from which the expanded private key
is derived deterministically when the key is loaded.

**Supports PKR**: whether the signer's public key can be recovered from the signature (public key recovery), so that it
does not have to travel with the signature. When it cannot, the public key, or its post-quantum half for a hybrid, is
carried alongside the signature (see [the public key field](../04-transactions.md#the-public-key-field)).

> **Falcon and PKR.** The Falcon specification also defines a second, *key-recovery* mode, in which the public key can
> be recovered from the signature, at the cost of a larger signature. It is not implemented here: `FALCON512` uses the
> standard mode (the one Bouncy Castle implements), which does not support PKR.

Identifier ranges: `0x00 0x0X` classical, `0x003X` ML-DSA, `0x004X` Falcon, `0x006X` secp256k1 with ML-DSA hybrids,
`0x007X` secp256k1 with Falcon hybrids.

> In the source, the constructor arguments are `(id, name, privateKeyLength, publicKeyLength, signatureLength,
> seedLength)`. The private key length comes **before** the public key length.

All post-quantum code uses **Bouncy Castle** (`bcprov-jdk18on` 1.80.x) through its low-level `org.bouncycastle.pqc.crypto`
API. ECDSA uses Besu's native secp256k1 and secp256r1 libraries when they are available.

## ECDSA: SECP256K1 and SECP256R1

These are upstream's algorithms. They now also implement `DigitalSignatureAlgorithm` and `PublicKeyRecoverable`.

- **`SECP256K1`** signs deterministically (RFC 6979). **`SECP256R1`** uses a random nonce.
- Both sign a 32-byte message, normally a Keccak-256 hash.
- A signature remembers its curve. The low-`s` malleability check uses the half order of that curve.
- `SECP256R1` support (also as an account DSA) was added together with the rule that `--node-dsa` must sign on the
  genesis `ecCurve` (see [Configuration](../10-configuration.md#genesis-eccurve-and-node-dsa)).

## ML-DSA

Implemented by `crypto/algorithms/.../algorithms/MLDSA.java`. Three parameter sets are available: `MLDSA44`,
`MLDSA65` and `MLDSA87`.

| Aspect | Behaviour |
|---|---|
| Variant | Pure ML-DSA with an empty context string, applied to the message passed in (a 32-byte hash for transactions and consensus). Not HashML-DSA |
| Randomness | **Deterministic** signing (FIPS 204 deterministic variant: no random input is given to the signer) |
| Thread safety | A new Bouncy Castle `MLDSASigner` is created for each signature and each verification, because the signer keeps SHAKE state |
| Private key | Stored in the **expanded** form (`rho ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0`). A 32-byte input is treated as a **seed** and expanded when loaded |
| Public key | Always derived from the private key when a key is loaded. A key built from bytes (`MLDSAPublicKey.create`, which `KeyFactory.createPublicKey` and, through it, the transaction, code delegation and consensus decoders use) must have the exact length of its parameter set, 1312, 1952 or 2592 bytes; any other length is refused with `Expected a MLDSA44 public key of 1312 bytes, got 100` |
| Verification | Returns `false`, rather than throwing, for a key of the wrong length or any input Bouncy Castle rejects, as Falcon does. A transaction does not get this far with a wrong-length key: the decoder refuses it first |
| Key generation | Bouncy Castle `MLDSAKeyPairGenerator` with Besu's `SecureRandom` |

## Falcon-512

Implemented by `crypto/algorithms/.../algorithms/Falcon.java`, parameterized by `DSAParametersSet`. Only
`FALCON512` is registered.

| Aspect | Behaviour |
|---|---|
| Encoding | Falcon round-3 encoding, as produced by Bouncy Castle |
| Randomness | **Randomized**: each signature uses a fresh nonce from `SecureRandom` |
| Signature length | Variable, typically 650–660 bytes. Accepted up to **752** bytes, the liboqs maximum for Falcon-512, and never padded |
| Private key | `f ‖ g ‖ F ‖ h` (384 + 384 + 512 + 896 = 2176 bytes). The public key `h` is appended on purpose, because Bouncy Castle cannot derive it from `f, g, F` |
| Public key | `h` (896 bytes), without the 1-byte header used by FIPS-style encodings |
| Verification | Returns `false`, rather than throwing, for a wrong key length, an empty signature or a malformed encoding |
| Secrets | Private keys compare in constant time and are redacted in `toString()` |

> **Falcon status.** Falcon-512 is fully supported for **account** signatures (transactions and code delegations). As a
> **node** DSA (`SECP256K1-FALCON512`), it works for consensus but has peer-discovery limitations. See
> [Networking](../06-networking.md#falcon-node-keys).

## Hybrids

`SECP256K1-MLDSA44` and `SECP256K1-FALCON512` combine ECDSA on secp256k1 with a post-quantum algorithm. Both are built by
`HybridStrongNestingConcatenation` and described in [Hybrid signatures](hybrid-signatures.md). Hybrids are available only
on networks whose genesis `ecCurve` is secp256k1 (the default).

## Where each algorithm can be used

| DSA | Account DSA (transactions) | Node DSA (consensus, P2P) |
|---|---|---|
| `SECP256K1` | ✓ (also standard transactions) | ✓ default |
| `SECP256R1` | ✓ | ✓ on `ecCurve: secp256r1` networks |
| `MLDSA44/65/87` | ✓ | — (see note) |
| `FALCON512` | ✓ | — (see note) |
| `SECP256K1-MLDSA44` | ✓ | ✓ |
| `SECP256K1-FALCON512` | ✓ | ⚠ experimental (static peers only) |

Note: a node whose key is purely post-quantum cannot complete the RLPx handshake, which needs an elliptic-curve key for
ECDHE. Use a hybrid as the node DSA. See [Key management](key-management.md#key-agreement-ecdh).

## Adding an algorithm

**Crypto agility.** Besu is crypto-agile for **account** and **consensus** signatures. Transactions, code delegations,
consensus messages, commit seals, Clique seals, the CLI options, `vnt_getAccountsSupportedDSAs` and the metrics work
through the `DigitalSignatureAlgorithm` abstraction and the `dsaType` identifier, so adding an algorithm does not require
re-engineering them: it is a matter of implementing it and registering it in the places listed below.

It is **not yet fully crypto-agile**: the P2P layer is still tied to specific algorithms. The RLPx handshake needs a
secp256k1 key for ECDH, discv4 packets need a fixed-length signature, and the `vnt` node record (ENR) is hard-wired to
`SECP256K1-MLDSA44` (`NodeRecordManager`, `EnrSignatureValidator`, `BootnodeRecordFactory`, `EthereumNodeRecord`). A
new algorithm can therefore be used as an account DSA, but not as a node DSA on a P2P network, without changes there.
Re-engineering the P2P layer to remove these assumptions is left for future research (see
[Networking](../06-networking.md)).

### Steps

1. **Implement the algorithm.** Implement `DigitalSignatureAlgorithm` (and `PublicKeyRecoverable` if the algorithm
   supports public key recovery), plus its `Signature`, `PublicKey` and `PrivateKey` types. `isValid(context)` on the
   signature should check its structure (for example its length), and verification should return `false` rather than
   throw on malformed input. If the algorithm wraps a Bouncy Castle parameter set, map the new name to it (as
   `MLDSA.RENAMING_TO_LIB` does for ML-DSA).
2. **Add a constant to `DSAParametersSet`** with a free identifier in the right range (see
   [Identifiers and sizes](#identifiers-and-sizes)), and its private key, public key, signature and seed lengths. Use
   `null` for a signature length that is not fixed. The name is the one the CLI options and the logs use.
3. **Register the new DSA in `SupportedAlgorithms`.** This is what makes the name usable with `--node-dsa` and
   `--accounts-supported-dsas`.
4. **Teach `KeyFactory`** to create the new private and public keys from bytes, and to derive the public key from the
   private key.
5. **Teach `SignatureFactory`** to create the new signature type from bytes.
6. **For a hybrid**, also:
   - build it with a combiner in `SupportedAlgorithms`, with the recoverable (ECDSA) half first. The existing hybrids
     use `HybridStrongNestingConcatenation`, but the combiner is not fixed: another one, different from Strong Nesting,
     can be implemented as a new `HybridDigitalSignatureAlgorithm`. The rest of the code recognizes hybrids through
     that interface (`getFirstAlgorithm()` / `getSecondAlgorithm()`), for example to decide which half of the public
     key is carried. A combiner whose signature is not a concatenation of the two halves also needs its own signature
     type and decoding in `SignatureFactory`;
   - teach `KeyFactory` and `SignatureFactory` to split the concatenated key and signature. A variable-length half
     (such as Falcon) must come **last**, so that the other half can be cut out at a fixed offset;
   - choose an identifier in `0x006X` (secp256k1 + ML-DSA) or `0x007X` (other hybrids).
7. **Nothing to change** in the transaction encoders and decoders, the validator, consensus or JSON-RPC: they work from
   the `dsaType` and the algorithm's interfaces. `PublicKeyEncoder` and `PublicKeyDecoder` decide whether a public key
   is carried from `PublicKeyRecoverable` and the sizes in `DSAParametersSet`.
8. **Add tests:**
   - unit tests for the algorithm itself (sign, verify, key round trip, malformed input), like `MLDSATest`,
     `FalconTest` or `Secp256k1Falcon512HybridTest` (`crypto/algorithms`);
   - the new parameter set in the parameterized consensus tests that list algorithms explicitly:
     `CommitValidatorNonRecoverableTest` (QBFT), `SignedDataValidatorNonRecoverableTest` (IBFT 2.0),
     `CliqueBlockCreatorNonRecoverableTest` and `CliqueExtraDataNonRecoverableTest` (Clique);
   - the name in the `algorithms` list of `gradle/consensus-dsa-integration-tests.gradle` (and in `pqcAlgorithms` if it
     is post-quantum), which registers an `integrationTest<NAME>` task and adds it to `integrationTestPqc` /
     `integrationTestAllDsas`;
   - a flexible transaction test that encodes, decodes and verifies a transaction signed with the new DSA, like
     `FlexibleEIP1559Falcon512TransactionTest` (`ethereum/core`).
9. **Update the documentation:** the [Identifiers and sizes](#identifiers-and-sizes) table,
   [Where each algorithm can be used](#where-each-algorithm-can-be-used), the
   [size impact](../12-metrics-and-performance.md#size-impact) table and the
   [compatibility matrix](../10-configuration.md#compatibility-matrix).

---

[🏠 Index](../README.md) · [⚡ Quick start](../00-quick-start.md) · [↑ Cryptography](README.md) · [← Previous: Cryptography](README.md) · [Next: Hybrid signatures →](hybrid-signatures.md)
