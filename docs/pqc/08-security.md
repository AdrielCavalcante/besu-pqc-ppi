[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: JSON-RPC API](07-json-rpc-api.md) · [Next: Installation →](09-installation.md)

---

# Security considerations

## Contents

- [Threat model](#threat-model)
- [Security properties by DSA](#security-properties-by-dsa)
- [Protocol protections](#protocol-protections)
- [Hybrid verification and key binding](#hybrid-verification-and-key-binding)
- [Denial-of-service considerations](#denial-of-service-considerations)
- [Implementation notes](#implementation-notes)
- [Out of scope and limitations](#out-of-scope-and-limitations)
- [Operational recommendations](#operational-recommendations)

## Threat model

| Adversary | Capability | Protected by |
|---|---|---|
| Classical attacker | forge or tamper with signatures, replay, malleate, substitute algorithms or keys | ECDSA and post-quantum signatures, signing hashes that cover `dsaType` and the public key, malleability checks |
| Quantum attacker ("Q-day") | compute ECDSA private keys from public keys | ML-DSA / Falcon, or the post-quantum half of a hybrid, for accounts and node keys |
| Malicious block proposer | include transactions with forged signatures, forge seals | signature checks during block processing, verified commit seals and proposer seals |
| Malicious peer | send malformed or oversized messages, spoof identities | length checks, signed discovery packets and records, consensus message verification |

## Security properties by DSA

| DSA | Classical security | Quantum security | Notes |
|---|---|---|---|
| `SECP256K1`, `SECP256R1` | ~128 bit | **none** | upstream behaviour |
| `MLDSA44` / `65` / `87` | NIST category 2 / 3 / 5 | NIST category 2 / 3 / 5 | relies on lattice assumptions only |
| `FALCON512` | NIST category 1 | NIST category 1 | relies on lattice assumptions only |
| `SECP256K1-MLDSA44` | max(ECDSA, ML-DSA-44) | ML-DSA-44 | secure while *either* half is unbroken |
| `SECP256K1-FALCON512` | max(ECDSA, Falcon-512) | Falcon-512 | as above |

An account is only as safe as the algorithm used by its **address**. A hybrid address commits to both keys, so a quantum
attacker who obtains the ECDSA private key still cannot sign for it. ECDSA accounts remain vulnerable to quantum
attackers; users must move their funds to post-quantum or hybrid addresses.

## Protocol protections

- **Algorithm binding.** `dsaType` is the first field of every signing preimage, both for transactions and for flexible
  code delegations. Changing the algorithm invalidates the signature.
- **Key binding.** When a public key is carried, the signing preimage covers it (in transactions, flexible delegations
  and Clique seals). In discovery packets, the packet hash covers it. The address is derived from the **resolved** key,
  so carrying someone else's key cannot impersonate them without a valid signature for that key.
- **Recovered parts are never trusted from input.** For recoverable algorithms, and for the ECDSA half of hybrids, the
  key is always recovered from the signature, even if the input supplies one. A full composite key in a transaction is
  rejected.
- **Malleability.** ECDSA signatures must have a low `s` on their own curve (`SignatureValidationContext`).
- **Unresolvable signers are rejected.** A signature whose key cannot be recovered is reported as `INVALID_SIGNATURE`,
  never as an internal error. One example is a secp256k1 signature on a secp256r1 network. The failure is cached, so an
  attacker cannot make the node repeat expensive recovery attempts.
- **Verification in block processing.** Transactions are verified again when blocks are built, validated and imported,
  so a malicious proposer cannot include a forged non-recoverable transaction.
- **Forged commit seals** are discarded, and the block must still reach quorum with valid seals.
- **Account policy.** `--accounts-supported-dsas` limits which algorithms a node accepts. Disabled types are rejected
  while the transaction is decoded, before any expensive work.

## Hybrid verification and key binding

`HybridStrongNestingConcatenation.verify()` checks only the halves whose algorithm **cannot** recover keys. The ECDSA
half is authenticated by public-key recovery in `PublicKeyHandler.resolvePublicKey`: the key recovered from `σ₁` is, by
construction, the key that produced `σ₁`, and it becomes part of the composite key and of the address.

This is safe as long as callers follow the rule used everywhere in the fork:

> Resolve the composite key with `PublicKeyHandler.resolvePublicKey` (recovering the ECDSA half from the signature), then
> verify, then derive the signer from the resolved key. **Never** call `verify()` with an ECDSA half taken from
> untrusted input.

Strong nesting means that the post-quantum half signs `hash ‖ σ₁`, so `σ₁` cannot be replaced without invalidating
`σ₂`.

## Denial-of-service considerations

| Vector | Mitigation |
|---|---|
| Large transactions (2–5 KB signatures, 1–2.6 KB keys) | The pool accounts for the real memory size of keys and signatures. Block gas limits still apply |
| Expensive verification | Verification results are cached by transaction hash (100 000 entries). ECDSA needs no separate verification step. |
| Disabled or unknown DSAs | Rejected while decoding, before verification |
| Malformed lengths | Exact length checks for keys and ML-DSA and hybrid signatures; Falcon signatures are limited to 752 bytes; Clique footer lengths are bounded |
| Repeated failed key recovery | Failure is cached per transaction |
| Large discovery packets | Packets are limited to 8192 bytes and the number of NEIGHBORS entries per response is bounded |

**Gas does not price verification.** A flexible transaction costs as much gas as a standard one, even though verifying it
is more expensive and it takes more bandwidth. On permissioned networks this is acceptable. On open networks, an attacker
could fill blocks with transactions that are cheap in gas but expensive to verify. See
[Metrics and performance](12-metrics-and-performance.md#dsa-microbenchmark-verification-cost-in-gas) for the measured costs.

## Implementation notes

- **Libraries.** Post-quantum algorithms come from Bouncy Castle (1.80.x, low-level `pqc.crypto` API). No custom
  cryptographic primitives are implemented.
- **Randomness.** ML-DSA signs deterministically (no RNG dependency at signing time). Falcon and SECP256R1 sign with a
  random nonce from `SecureRandom`. Key generation uses Besu's `SecureRandomProvider`.
- **Side channels.** Constant-time behaviour is that of Bouncy Castle's Java implementation. Falcon's floating-point
  sampling in a JVM has not been audited for timing leakage.
- **Key storage.** Node keys are stored unencrypted in hexadecimal, as upstream does for ECDSA keys. Protect the file
  with file-system permissions. External `SecurityModule` plugins (HSMs) support ECDSA keys only.
- **No audit.** This fork is a research and development prototype and has not undergone an independent security audit.

## Out of scope and limitations

- **Transport key establishment is classical.** RLPx and discv5 derive their session keys from secp256k1 ECDHE. An
  attacker who records traffic today and has a quantum computer later can recover those keys and decrypt the traffic
  ("harvest now, decrypt later"). Signatures and consensus integrity are
  not affected.
- **The RLPx handshake authenticates only the ECDSA half of a hybrid node ID.** The post-quantum identity is proven in
  discovery and in consensus messages, not in the transport handshake.
- **Falcon node keys** are experimental (no discovery). See [Networking](06-networking.md#falcon-node-keys).
- **Hard-fork scope.** Flexible transactions are accepted under Prague only. See
  [Transactions](04-transactions.md#hard-fork-activation).
- **No algorithm agility on a running chain.** Changing the node DSA requires a new network.

## Operational recommendations

1. Use **`SECP256K1-MLDSA44`** as the node DSA for post-quantum networks.
2. Enable the same `--accounts-supported-dsas` on every validator.
3. Prefer hybrid account DSAs during the transition, and pure post-quantum DSAs where ECDSA tooling is not needed.
4. Keep the network permissioned. Use static peers or a flat network. With a post-quantum node DSA, discovery packets
   usually exceed the usual MTU (about 1500 bytes) and are fragmented at the IP level. If the underlying network does
   not allow UDP fragmentation (e.g. some NATs, firewalls and load balancers), the fragments are dropped, the packets
   are lost and peers fail to discover each other (see
   [Networking → Discovery v4 packets](06-networking.md#discovery-v4-packets)).
5. Protect node key files (`chmod 600`), and back them up: hybrid keys cannot be regenerated from a mnemonic.

---

[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: JSON-RPC API](07-json-rpc-api.md) · [Next: Installation →](09-installation.md)
