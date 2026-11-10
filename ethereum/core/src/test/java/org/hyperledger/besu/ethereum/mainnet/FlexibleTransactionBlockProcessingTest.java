/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.mainnet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.hyperledger.besu.config.GenesisConfig;
import org.hyperledger.besu.config.JsonUtil;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.BlockProcessingResult;
import org.hyperledger.besu.ethereum.ProtocolContext;
import org.hyperledger.besu.ethereum.chain.Blockchain;
import org.hyperledger.besu.ethereum.core.Block;
import org.hyperledger.besu.ethereum.core.BlockBody;
import org.hyperledger.besu.ethereum.core.BlockHeader;
import org.hyperledger.besu.ethereum.core.BlockHeaderTestFixture;
import org.hyperledger.besu.ethereum.core.ExecutionContextTestFixture;
import org.hyperledger.besu.ethereum.core.MutableWorldState;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.mainnet.parallelization.MainnetParallelBlockProcessor;
import org.hyperledger.besu.ethereum.processing.TransactionProcessingResult;
import org.hyperledger.besu.ethereum.transaction.TransactionInvalidReason;
import org.hyperledger.besu.evm.blockhash.BlockHashLookup;
import org.hyperledger.besu.metrics.noop.NoOpMetricsSystem;
import org.hyperledger.besu.plugin.services.storage.DataStorageFormat;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Blocks are processed without passing through the transaction pool, so the signature of a flexible
 * transaction has to be verified there too. A non-recoverable algorithm takes the sender from the
 * public key the transaction carries, so without that check a block could spend from any account
 * whose key is known.
 */
class FlexibleTransactionBlockProcessingTest {

  private static final String GENESIS_RESOURCE =
      "/org/hyperledger/besu/ethereum/mainnet/genesis-flexible-tx-it.json";

  private static final DSAParametersSet SECP = DSAParametersSet.SECP256K1;
  private static final DSAParametersSet MLDSA = DSAParametersSet.MLDSA44;
  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  private static final BigInteger CHAIN_ID = BigInteger.valueOf(1337);
  private static final Address RECIPIENT =
      Address.fromHexString("0x000000000000000000000000000000000000beef");
  private static final Wei BALANCE = Wei.fromEth(10);
  private static final Wei VALUE = Wei.fromEth(1);
  // Covers the intrinsic gas of every DSA type, so a transaction is judged by its signature.
  private static final long GAS_LIMIT = 150_000L;

  private ProtocolContext protocolContext;
  private ProtocolSchedule protocolSchedule;
  private Blockchain blockchain;
  private MutableWorldState worldState;

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(SECP, MLDSA, HYBRID));
    config.setNodeActiveDSA(SECP.getName());
    DSAProviderFactory.setDsaProvider(config, null);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @ParameterizedTest(name = "parallel={0}")
  @ValueSource(booleans = {false, true})
  void rejectsABlockWithAnMlDsaTransactionCarryingSomeoneElsesKey(final boolean parallel) {
    final KeyPair attacker = algorithm(MLDSA).generateNodeKeyPair();
    final KeyPair victim = algorithm(MLDSA).generateNodeKeyPair();
    startChainFunding(victim.getPublicKey());

    // The sender is keccak(carried key), so the transaction claims the victim's account, while the
    // signature -- well formed, over the right hash -- is the attacker's.
    final Transaction forged = signed(MLDSA, attacker, Optional.of(victim.getPublicKey()));
    assertThat(forged.getSender()).isEqualTo(Address.extract(victim.getPublicKey()));

    assertRejectedForItsSignature(processBlock(parallel, forged));
    assertThat(worldState.get(RECIPIENT)).isNull();
  }

  @ParameterizedTest(name = "parallel={0}")
  @ValueSource(booleans = {false, true})
  void rejectsABlockWithAHybridTransactionWhoseMlDsaHalfWasTamperedWith(final boolean parallel) {
    final KeyPair sender = algorithm(HYBRID).generateNodeKeyPair();
    startChainFunding(sender.getPublicKey());

    assertRejectedForItsSignature(processBlock(parallel, tamperedHybrid(sender)));
  }

  @Test
  void executesAnMlDsaTransactionSignedByItsSender() {
    final KeyPair sender = algorithm(MLDSA).generateNodeKeyPair();
    startChainFunding(sender.getPublicKey());

    final TransactionProcessingResult result =
        processTransaction(signed(MLDSA, sender, Optional.of(sender.getPublicKey())));

    assertThat(result.isSuccessful()).as(result.getValidationResult().toString()).isTrue();
  }

  @Test
  void executesAHybridTransactionSignedByItsSender() {
    final KeyPair sender = algorithm(HYBRID).generateNodeKeyPair();
    startChainFunding(sender.getPublicKey());

    final TransactionProcessingResult result =
        processTransaction(signed(HYBRID, sender, Optional.of(mlDsaHalfOf(sender))));

    assertThat(result.isSuccessful()).as(result.getValidationResult().toString()).isTrue();
  }

  /** Prague brought flexible transactions; every fork after it must keep accepting them. */
  @ParameterizedTest(name = "{0}")
  @ValueSource(strings = {"Prague", "Osaka", "Amsterdam"})
  void executesAFlexibleTransactionInEveryForkFromPragueOn(final String fork) {
    final KeyPair sender = algorithm(MLDSA).generateNodeKeyPair();
    startChainFunding(Optional.of(fork), sender.getPublicKey());

    assertThat(protocolSchedule.getByBlockHeader(nextHeader()).getHardforkId().description())
        .isEqualTo(fork);
    final TransactionProcessingResult result =
        processTransaction(signed(MLDSA, sender, Optional.of(sender.getPublicKey())));
    assertThat(result.isSuccessful()).as(result.getValidationResult().toString()).isTrue();
  }

  /**
   * With a large payload the EIP-7623 calldata floor exceeds the intrinsic gas. The floor starts
   * from the base cost of the DSA type, so the transaction still pays for its signature: 82,553 for
   * ML-DSA-44 plus 10,000 non-zero bytes at 40 gas (4 tokens of 10 gas each), not 21,000 plus them.
   */
  @Test
  void chargesTheCalldataFloorOnTopOfTheBaseCostOfTheDsaType() {
    final KeyPair sender = algorithm(MLDSA).generateNodeKeyPair();
    startChainFunding(sender.getPublicKey());

    final TransactionProcessingResult result =
        processTransaction(
            signed(
                MLDSA,
                sender,
                Optional.of(sender.getPublicKey()),
                Bytes.repeat((byte) 0x01, 10_000),
                600_000L));

    assertThat(result.isSuccessful()).as(result.getValidationResult().toString()).isTrue();
    assertThat(result.getGasSpent()).isEqualTo(82_553L + 400_000L);
  }

  /** The signer key is recovered whole from the signature, which authenticates it. */
  @Test
  void executesASecp256k1FlexibleTransaction() {
    final KeyPair sender = algorithm(SECP).generateNodeKeyPair();
    startChainFunding(sender.getPublicKey());

    final TransactionProcessingResult result =
        processTransaction(signed(SECP, sender, Optional.of(sender.getPublicKey())));

    assertThat(result.isSuccessful()).as(result.getValidationResult().toString()).isTrue();
  }

  @Test
  void doesNotExecuteAnMlDsaTransactionCarryingSomeoneElsesKey() {
    final KeyPair attacker = algorithm(MLDSA).generateNodeKeyPair();
    final KeyPair victim = algorithm(MLDSA).generateNodeKeyPair();
    startChainFunding(victim.getPublicKey());

    final TransactionProcessingResult result =
        processTransaction(signed(MLDSA, attacker, Optional.of(victim.getPublicKey())));

    assertThat(result.isInvalid()).isTrue();
    assertThat(result.getValidationResult().getInvalidReason())
        .isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
  }

  private static void assertRejectedForItsSignature(final BlockProcessingResult result) {
    assertThat(result.isSuccessful()).isFalse();
    assertThat(result.errorMessage)
        .hasValueSatisfying(
            message ->
                assertThat(message)
                    .contains("transaction invalid")
                    .containsIgnoringCase("signature"));
  }

  /**
   * Starts a chain whose genesis funds the given keys. The keys are generated per test, so they
   * cannot be in the genesis file; funding them after the fact would not reach the parallel
   * processor, which executes against the persisted parent state.
   */
  private void startChainFunding(final PublicKey... publicKeys) {
    startChainFunding(Optional.empty(), publicKeys);
  }

  /** As above, with the given fork, e.g. "Osaka", active from genesis on top of Prague. */
  private void startChainFunding(final Optional<String> fork, final PublicKey... publicKeys) {
    final ObjectNode genesis = JsonUtil.objectNodeFromString(readGenesis());
    fork.ifPresent(
        name ->
            ((ObjectNode) genesis.get("config")).put(name.toLowerCase(Locale.ROOT) + "Time", 0));
    final ObjectNode alloc = (ObjectNode) genesis.get("alloc");
    for (final PublicKey publicKey : publicKeys) {
      alloc
          .putObject(Address.extract(publicKey).toString())
          .put("balance", BALANCE.toShortHexString());
    }

    // built after the provider is set: the transaction validator takes it in its constructor
    final ExecutionContextTestFixture fixture =
        ExecutionContextTestFixture.builder(GenesisConfig.fromConfig(genesis))
            .dataStorageFormat(DataStorageFormat.BONSAI)
            .build();
    protocolContext = fixture.getProtocolContext();
    protocolSchedule = fixture.getProtocolSchedule();
    blockchain = fixture.getBlockchain();
    worldState = fixture.getStateArchive().getWorldState();
  }

  private static String readGenesis() {
    try (InputStream in =
        FlexibleTransactionBlockProcessingTest.class.getResourceAsStream(GENESIS_RESOURCE)) {
      return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (final IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private BlockHeader nextHeader() {
    final BlockHeader parent = blockchain.getChainHeadHeader();
    return new BlockHeaderTestFixture()
        .number(parent.getNumber() + 1L)
        .parentHash(parent.getHash())
        .gasLimit(30_000_000L)
        .baseFeePerGas(Wei.of(5))
        .buildHeader();
  }

  private TransactionProcessingResult processTransaction(final Transaction transaction) {
    final BlockHeader header = nextHeader();
    return protocolSchedule
        .getByBlockHeader(header)
        .getTransactionProcessor()
        .processTransaction(
            worldState.updater(),
            header,
            transaction,
            header.getCoinbase(),
            mock(BlockHashLookup.class),
            TransactionValidationParams.processingBlock(),
            Wei.ZERO);
  }

  /**
   * The state root is left at the fixture's default: a rejected transaction fails the block before
   * the root is checked.
   */
  private BlockProcessingResult processBlock(
      final boolean parallel, final Transaction transaction) {
    final BlockHeader header = nextHeader();
    final Block block =
        new Block(header, new BlockBody(List.of(transaction), List.of(), Optional.empty()));

    final ProtocolSpec spec = protocolSchedule.getByBlockHeader(header);
    final BlockProcessor processor =
        parallel
            ? new MainnetParallelBlockProcessor(
                spec.getTransactionProcessor(),
                spec.getTransactionReceiptFactory(),
                Wei.ZERO,
                BlockHeader::getCoinbase,
                true,
                protocolSchedule,
                BalConfiguration.DEFAULT,
                new NoOpMetricsSystem())
            : new MainnetBlockProcessor(
                spec.getTransactionProcessor(),
                spec.getTransactionReceiptFactory(),
                Wei.ZERO,
                BlockHeader::getCoinbase,
                true,
                protocolSchedule,
                BalConfiguration.DEFAULT);
    return processor.processBlock(protocolContext, blockchain, worldState, block);
  }

  private static Transaction tamperedHybrid(final KeyPair sender) {
    final Transaction signed = signed(HYBRID, sender, Optional.of(mlDsaHalfOf(sender)));
    // the last byte belongs to the ML-DSA signature, which is never recovered
    final byte[] bytes = signed.getSignature().encodedBytes().toArray();
    bytes[bytes.length - 1] ^= 0x01;
    return unsigned(HYBRID, Optional.of(mlDsaHalfOf(sender)))
        .signature(SignatureFactory.createSignatureFromBytes(Bytes.wrap(bytes), HYBRID))
        .build();
  }

  /**
   * A transaction carrying {@code carriedKey}, signed by {@code signer} over its signing hash. The
   * hash does not cover the signature, so it is taken from an otherwise identical transaction.
   */
  private static Transaction signed(
      final DSAParametersSet params, final KeyPair signer, final Optional<PublicKey> carriedKey) {
    return signed(params, signer, carriedKey, Bytes.EMPTY, GAS_LIMIT);
  }

  private static Transaction signed(
      final DSAParametersSet params,
      final KeyPair signer,
      final Optional<PublicKey> carriedKey,
      final Bytes payload,
      final long gasLimit) {
    final DigitalSignatureAlgorithm dsa = algorithm(params);
    final Bytes signingHash =
        Bytes.wrap(
            unsigned(params, carriedKey)
                .payload(payload)
                .gasLimit(gasLimit)
                .signature(dsa.sign(Bytes32.ZERO, signer.getPrivateKey()))
                .build()
                .getSigningHash());
    final Signature signature = dsa.sign(signingHash, signer.getPrivateKey());
    return unsigned(params, carriedKey)
        .payload(payload)
        .gasLimit(gasLimit)
        .signature(signature)
        .build();
  }

  private static Transaction.Builder unsigned(
      final DSAParametersSet params, final Optional<PublicKey> carriedKey) {
    return Transaction.builder()
        .type(TransactionType.FLEXIBLE_EIP1559)
        .dsaType(params.getId())
        .chainId(CHAIN_ID)
        .nonce(0)
        .maxPriorityFeePerGas(Wei.of(1))
        .maxFeePerGas(Wei.of(10))
        .gasLimit(GAS_LIMIT)
        .to(RECIPIENT)
        .value(VALUE)
        .payload(Bytes.EMPTY)
        .accessList(List.of())
        .providedPublicKey(carriedKey);
  }

  private static PublicKey mlDsaHalfOf(final KeyPair hybridKeyPair) {
    return ((CompositePublicKey) hybridKeyPair.getPublicKey()).getSecondKey();
  }

  private static DigitalSignatureAlgorithm algorithm(final DSAParametersSet params) {
    return new SupportedAlgorithms().getDSAByName(params.getName()).get();
  }
}
