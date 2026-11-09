[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Metrics and performance](12-metrics-and-performance.md) · [Next: Index →](README.md)

---

# Testing and compatibility

## Contents

- [Test suites added by the fork](#test-suites-added-by-the-fork)
- [Consensus integration tests under every DSA](#consensus-integration-tests-under-every-dsa)
- [End-to-end testing](#end-to-end-testing)
- [Compatibility with upstream Besu](#compatibility-with-upstream-besu)
- [Known limitations](#known-limitations)
- [Base version](#base-version)

## Test suites added by the fork

| Area | Tests (examples) | Module |
|---|---|---|
| Algorithms | `MLDSATest`, `MLDSAConcurrencyTest`, `MLDSAPrivateKeyTest`, `FalconTest`, `Secp256k1Falcon512HybridTest`, `SECPCurvesTest`, `UnrecoverableSignatureTest` | `crypto/algorithms` |
| Keys | `KeyExtractorTest`, `PublicKeyHandlerTest`, `CompositeKeyCodecTest`, `AddressFromHybridPublicKeyTest` | `crypto/algorithms`, `datatypes` |
| Configuration | `DigitalSignatureAlgorithmConfigurationTest`, `NodeDsaCurveTest`, `NodeDsaEcCurveTest` | `crypto/algorithms`, `app` |
| Metrics | `CSVWriterTest`, `MetricWritersTest`, `QbftMetricsLabelTest`, `IbftMetricsLabelTest` | several |
| Transactions | `FlexibleEIP1559Falcon512TransactionTest`, `FlexibleEIP1559Secp256k1Falcon512TransactionTest`, `PublicKeyDecoderTest`, `SignAndBuildTest`, `FlexibleTransactionBlockProcessingTest`, `FlexibleSignatureVerificationCacheTest` | `ethereum/core` |
| Code delegations | `CodeDelegationWireEncodingTest`, `CodeDelegationProvidedKeyTest`, `FlexibleCodeDelegationValidationTest` | `ethereum/core` |
| JSON-RPC | `VntGetAccountsSupportedDSAsTest`, `VntJsonRpcMethodsTest`, `FlexibleSecp256k1TransactionResultTest`, `CodeDelegationResultTest`, `EthSendRawTransactionDisabledDsaTest`, `EthSendRawTransactionUnrecoverableSignatureTest` | `ethereum/api` |
| Consensus | `SignedDataNonRecoverableTest`, `SignedDataValidatorNonRecoverableTest`, `CommitSealTest`, `CommitValidatorNonRecoverableTest`, `QbftExtraDataCodecSealEncodingTest`, `CliqueExtraDataNonRecoverableTest`, `CliqueBlockCreatorNonRecoverableTest` | `consensus/*` |
| P2P | `HybridNodeIdTest`, `HybridPacketTest`, `PacketSizeLimitTest`, `HybridNodeKeyHandshakeTest`, `NodeRecordManagerTest`, `EnrSignatureValidatorTest`, `VerifyingVntInterpreterTest`, `BootnodeRecordFactoryTest` | `ethereum/p2p` |

Most of these tests are parameterized over several DSAs, typically `SECP256K1`, `MLDSA44`, `FALCON512`,
`SECP256K1-MLDSA44` and `SECP256K1-FALCON512`.

## Consensus integration tests under every DSA

The QBFT and IBFT 2.0 integration tests simulate whole validator networks (with mocked peers). The fork runs the
**same** suites under each node DSA. The algorithm is selected by the system property `besu.consensus.test.dsa`, read by
`ActiveDsaExtension`, and the tasks are defined in `gradle/consensus-dsa-integration-tests.gradle`:

| Task | Runs the suite under |
|---|---|
| `integrationTest` | `SECP256K1`, or `-PconsensusTestDsa=<name>` |
| `integrationTestPqc` | `MLDSA44`, `SECP256K1-MLDSA44`, `FALCON512`, `SECP256K1-FALCON512` |
| `integrationTestAllDsas` | the above plus `SECP256R1` |
| `integrationTest<NAME>` | one algorithm, e.g. `integrationTestSECP256K1MLDSA44` |

```bash
./gradlew :consensus:qbft-core:integrationTestPqc :consensus:ibft:integrationTestPqc
```

Under non-ECDSA algorithms, signatures and keys are left out of the expected-message comparisons, because Falcon and
SECP256R1 signatures are randomized. `ValidatorContractTest` runs under `SECP256K1` only.

## End-to-end testing

Neither the upstream acceptance tests nor the CI workflows exercise post-quantum networks. End-to-end testing uses the
companion projects:

1. Start a network for each node DSA ([Running a network](11-usage/running-a-network.md)).
2. Send single transactions and batches with each account DSA ([Sending transactions](11-usage/sending-transactions.md)).
3. Check block inclusion, `eth_getTransactionByHash` and the [signature metrics](12-metrics-and-performance.md).

A suggested matrix:

| Node DSA | Wallet commands |
|---|---|
| `SECP256K1` | `EIP1559`, `FlexibleEIP1559` (ML-DSA), `FlexibleEIP1559 --hybridDsa SECP256K1-FALCON512` |
| `SECP256K1-MLDSA44` | the same |
| `SECP256R1` | `EIP1559 --ecCurve secp256r1`, `FlexibleEIP1559` |
| `SECP256K1-FALCON512` (experimental) | `FlexibleEIP1559` |

## Compatibility with upstream Besu

| Aspect | Compatible? |
|---|---|
| Standard transactions `0x00`–`0x04`, signed with ECDSA | ✓ unchanged |
| Block, `extraData`, consensus and P2P encodings with an ECDSA node DSA | ✓ byte-identical |
| Upstream test suites | ✓ restored to passing after the abstraction refactoring |
| JSON-RPC for standard transactions | ✓ unchanged |
| Flexible transactions `0x41`–`0x44` | ✗ unknown to upstream clients |
| Hybrid node IDs, discovery packets above 1280 bytes, `vnt` ENRs | ✗ |
| Commit seals and Clique `extraData` with non-recoverable node DSAs | ✗ |
| External `SecurityModule` plugins | ECDSA keys only |

## Known limitations

| Limitation | Reference |
|---|---|
| Signature gas prices measured on one machine, with pure-Java post-quantum code | [Transactions](04-transactions.md#gas) |
| `SECP256K1-FALCON512` node keys: no discovery | [Networking](06-networking.md#falcon-node-keys) |
| Pure post-quantum node keys cannot open RLPx sessions | [Key management](03-cryptography/key-management.md#key-agreement-ecdh) |
| Transport key establishment remains classical (ECDHE) | [Security](08-security.md#out-of-scope-and-limitations) |
| The node DSA cannot change on a running chain | [Consensus](05-consensus.md#network-wide-requirements) |
| IBFT 1.0 (legacy) supports ECDSA only | [Consensus](05-consensus.md#support-matrix) |
| `besu public-key export` supports ECDSA keys only | [Key management](03-cryptography/key-management.md#limitations) |
| `eth_sendTransaction`, `eth_call` and GraphQL do not support flexible fields | [JSON-RPC API](07-json-rpc-api.md#not-supported) |

## Base version

The fork is based on Besu **26.1.0**. Upstream release notes up to that version are in
[CHANGELOG.md](../../CHANGELOG.md). Changes specific to the fork are described in this documentation.

---

[🏠 Index](README.md) · [⚡ Quick start](00-quick-start.md) · [← Previous: Metrics and performance](12-metrics-and-performance.md) · [Next: Index →](README.md)
