[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Sending transactions](11-usage/sending-transactions.md) · [Next: Testing and compatibility →](13-testing.md)

---

# Metrics and performance

## Contents

- [Size impact](#size-impact)
- [Signature metrics (CSV)](#signature-metrics-csv)
- [DSA microbenchmark: verification cost in gas](#dsa-microbenchmark-verification-cost-in-gas)
- [Performance design](#performance-design)
- [Standard Besu metrics](#standard-besu-metrics)

## Size impact

Bytes that a signature adds to a payload, compared with ECDSA:

| DSA | Signature | Public key carried | Total | × ECDSA |
|---|---|---|---|---|
| `SECP256K1` | 65 | 0 | 65 | 1 |
| `FALCON512` | ≈ 655 | 896 | ≈ 1 551 | ≈ 24 |
| `SECP256K1-FALCON512` | ≈ 720 | 896 | ≈ 1 616 | ≈ 25 |
| `MLDSA44` | 2 420 | 1 312 | 3 732 | 57 |
| `SECP256K1-MLDSA44` | 2 485 | 1 312 | 3 797 | 58 |
| `MLDSA65` | 3 309 | 1 952 | 5 261 | 81 |
| `MLDSA87` | 4 627 | 2 592 | 7 219 | 111 |

A simple transfer is about 110 bytes with ECDSA and about 3.9 KB with `SECP256K1-MLDSA44`. The size affects block size,
gossip bandwidth, transaction pool memory and storage. It does not affect gas (see
[Transactions → Gas](04-transactions.md#gas)). With a hybrid node DSA, every consensus message and commit seal also
carries about 3.8 KB of signature and key.

## Signature metrics (CSV)

The node records the time taken by every signing, verification and public-key recovery operation in CSV files. The
classes are in `crypto/algorithms/.../crypto/pqc/metrics/` (`CSVWriter`, `MetricWriters`).

| File | Header | Written when |
|---|---|---|
| `/usr/app/sign-metrics.csv` | `DSASigningTime(ns),Algorithm,Context` | the node signs with its node key (consensus, seals, discovery, node records) |
| `/usr/app/verify-metrics.csv` | `DSAVerificationTime(ns),isSignatureValid,Algorithm,Context` | a signature is verified (transactions, consensus messages, seals, Clique headers, discovery packets, ENRs) |
| `/usr/app/pkr-metrics.csv` | `PKRTime(ns),isRecovered,Algorithm,Context` | a public key is recovered (transactions, delegations, RLPx handshake, ENRs) |

- **`Algorithm`** shows which part of a hybrid did the work. For example, `SECP256K1-(MLDSA44)` means the ML-DSA half was
  verified, and `(SECP256K1)-MLDSA44` means the ECDSA half was recovered.
- **`Context`** names the operation, for example `tx`, `delegation`, `qbft-commit`, `qbft-commit-seal`,
  `clique-block-header`, `discv4-packet`, `node-record` or `rlpx-handshake`.

Behaviour:

- Metrics are **always on** when `/usr/app/` is writable, which is the case in the Docker image used by
  [besu-qbft](11-usage/running-a-network.md). Elsewhere, the directory usually does not exist, and samples are silently
  discarded.
- Samples are written by one background daemon thread through a bounded queue (100 000 entries). When the queue is full,
  samples are dropped, with a single warning. Writing metrics never blocks consensus.
- Files are appended across restarts. A file with an outdated header is renamed with a timestamp suffix.

In besu-qbft, `/usr/app` is the node's directory, so the files appear in `node-N/` on the host:

```bash
head -3 besu-qbft/node-1/verify-metrics.csv
```

```text
DSAVerificationTime(ns),isSignatureValid,Algorithm,Context
412350,yes,SECP256K1-(MLDSA44),tx
198220,yes,SECP256K1-(MLDSA44),qbft-commit
```

The values above illustrate the format. They are not reference measurements.

## DSA microbenchmark: verification cost in gas

Verifying a post-quantum signature is more expensive than recovering an ECDSA key. The microbenchmark measures that cost
and expresses it in gas. Its `gas (relative)` column is the CPU part of the base cost each `dsaType` pays (see
[Gas](04-transactions.md#gas)); re-run it before changing those prices.

Sources, in `crypto/algorithms/src/jmh/java/org/hyperledger/besu/crypto/`:

| Class | Role |
|---|---|
| `SignatureCostBenchmark` | A JMH benchmark parameterized over every `DSAParametersSet` |
| `SignatureGasReport` | Runs the benchmark and prints the gas table |

### Running it

```bash
./gradlew :crypto:algorithms:signatureGasReport
```

To measure only some algorithms (the `SECP256K1` baseline must be included):

```bash
./gradlew :crypto:algorithms:signatureGasReport -PjmhArgs="-p dsaType=SECP256K1,MLDSA44,SECP256K1-MLDSA44"
```

The default settings are 5 × 1 s warm-up, 10 × 1 s measurement and 3 forks per algorithm, so a full run takes several
minutes. Run it on an idle machine.

### What it measures

- The cost of **authenticating one signature the way the node does**:
  - for recoverable algorithms (`SECP256K1`, `SECP256R1`), public-key recovery;
  - for the others, `verify()`;
  - for hybrids, both halves **one after the other**: recovery of the ECDSA half, then verification of the post-quantum
    half over `hash ‖ σ₁`. This gives CPU cost, not the parallel wall-clock time of the node.
- 64 different key/message/signature fixtures, each checked at set-up to authenticate correctly.
- The validator's verification cache is bypassed, so this is the cost of a transaction seen for the first time.

### Reading the report

| Column | Meaning |
|---|---|
| `dsaType` | the algorithm |
| `time (us/op)` | average time per authentication, in microseconds |
| `± error` | 99.9 % confidence interval |
| `ratio` | time relative to `SECP256K1` |
| `gas (relative)` | `3000 × ratio`: anchored to the 3000 gas that `ECRECOVER` costs. Independent of the machine |
| `conserv. (rel.)` | `3000 × (time + error) / (baseline − error)`: an upper bound to round the price up to |
| `gas (absolute)` | `time × 100 Mgas/s` (1 gas = 10 ns, the target of Besu's `evmtool`). Depends on the machine |

All algorithms are measured in the same run, so load on the machine mostly cancels out in the relative columns. Prefer
`gas (relative)` or `conserv. (rel.)` when comparing algorithms or proposing prices.

## Performance design

Measures taken so that post-quantum verification can run on every node and at every stage (see
[Transactions → Validation](04-transactions.md#where-transaction-signatures-are-checked)):

| Measure | Effect |
|---|---|
| Account DSA instances built **once** at start-up and shared | Previously, building instances took about 22 ms per lookup for `SECP256K1-MLDSA44`, 84 % of QBFT CPU time |
| Successful verifications cached by transaction hash (100 000 entries) | Each transaction is verified once per node, although it passes through pool admission, selection, proposal validation and import |
| Sender cache checked before key resolution | No repeated key recovery |
| Recoverable DSAs skip `verify()` | Recovery already authenticates the signature |
| Hybrid halves verified in parallel | Lower latency for hybrid verification |
| Consensus messages decoded once | Each message is verified once instead of twice |
| Metrics on a background thread with a bounded queue | Writing metrics cannot stall the node |
| Pool memory accounting includes keys and signatures | Pool limits stay accurate with multi-kilobyte transactions |

## Standard Besu metrics

The standard Besu metrics (`--metrics-enabled`) are unchanged.

---

[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Sending transactions](11-usage/sending-transactions.md) · [Next: Testing and compatibility →](13-testing.md)
