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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECP256K1;
import org.hyperledger.besu.crypto.SECP256R1;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.DsaNotEnabledException;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.BlobType;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.GasLimitCalculator;
import org.hyperledger.besu.ethereum.core.CodeDelegation;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.mainnet.feemarket.FeeMarket;
import org.hyperledger.besu.ethereum.transaction.TransactionInvalidReason;
import org.hyperledger.besu.evm.gascalculator.PragueGasCalculator;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Standard transactions and code delegations carry no DSA type and are signed with the network's
 * curve. Leaving that curve out of the account-supported DSAs refuses them, as it refuses flexible
 * ones of a type left out.
 */
class StandardSignatureCurveEnabledTest {

  private static final BigInteger CHAIN_ID = BigInteger.valueOf(1337);
  private static final Address DELEGATE =
      Address.fromHexString("0x000000000000000000000000000000000000beef");

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
    SignatureAlgorithmFactory.resetInstance();
  }

  @Test
  void refusesAStandardTransactionWhenSecp256k1IsNotEnabled() throws Exception {
    final MainnetTransactionValidator validator = validatorEnabling(DSAParametersSet.MLDSA44);

    final ValidationResult<TransactionInvalidReason> result =
        validator.validate(
            standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair()),
            Optional.of(Wei.ONE),
            Optional.empty(),
            TransactionValidationParams.transactionPool());

    assertThat(result.getInvalidReason()).isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
    assertThat(result.getErrorMessage()).contains("SECP256K1");
  }

  /** Blocks are held to it too, not only the pool: a block proposer may not check. */
  @Test
  void refusesAStandardTransactionInABlockWhenSecp256k1IsNotEnabled() throws Exception {
    final MainnetTransactionValidator validator = validatorEnabling(DSAParametersSet.MLDSA44);

    assertThat(
            validator
                .validate(
                    standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair()),
                    Optional.of(Wei.ONE),
                    Optional.empty(),
                    TransactionValidationParams.processingBlock())
                .getInvalidReason())
        .isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
  }

  @Test
  void acceptsAStandardTransactionWhenSecp256k1IsEnabled() throws Exception {
    final MainnetTransactionValidator validator =
        validatorEnabling(DSAParametersSet.SECP256K1, DSAParametersSet.MLDSA44);

    assertThat(
            validator
                .validate(
                    standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair()),
                    Optional.of(Wei.ONE),
                    Optional.empty(),
                    TransactionValidationParams.transactionPool())
                .isValid())
        .isTrue();
  }

  /** eth_call and eth_estimateGas build a standard transaction with a fake signature. */
  @Test
  void simulationsAreNotHeldToTheEnabledCurve() throws Exception {
    final MainnetTransactionValidator validator = validatorEnabling(DSAParametersSet.MLDSA44);

    assertThat(
            validator
                .validate(
                    standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair()),
                    Optional.of(Wei.ONE),
                    Optional.empty(),
                    ImmutableTransactionValidationParams.builder()
                        .from(TransactionValidationParams.transactionSimulator())
                        .isSimulation(true)
                        .build())
                .isValid())
        .isTrue();
  }

  @Test
  void refusesAStandardTransactionWhenSecp256r1IsNotEnabledOnASecp256r1Network()
      throws Exception {
    SignatureAlgorithmFactory.resetInstance();
    SignatureAlgorithmFactory.setInstance(new SECP256R1());
    final MainnetTransactionValidator validator =
        validatorEnabling(DSAParametersSet.SECP256K1, DSAParametersSet.MLDSA44);

    final ValidationResult<TransactionInvalidReason> result =
        validator.validate(
            standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair()),
            Optional.of(Wei.ONE),
            Optional.empty(),
            TransactionValidationParams.transactionPool());

    assertThat(result.getInvalidReason()).isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
    assertThat(result.getErrorMessage()).contains("SECP256R1");
  }

  @Test
  void acceptsAStandardTransactionWhenSecp256r1IsEnabledOnASecp256r1Network() throws Exception {
    SignatureAlgorithmFactory.resetInstance();
    SignatureAlgorithmFactory.setInstance(new SECP256R1());
    final MainnetTransactionValidator validator = validatorEnabling(DSAParametersSet.SECP256R1);

    assertThat(
            validator
                .validate(
                    standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair()),
                    Optional.of(Wei.ONE),
                    Optional.empty(),
                    TransactionValidationParams.transactionPool())
                .isValid())
        .isTrue();
  }

  /** As upstream Besu, as in the evmtool and the reference tests. */
  @Test
  void withoutADsaProviderAStandardTransactionIsAccepted() {
    final MainnetTransactionValidator validator = validator();

    assertThat(
            validator
                .validate(
                    standardTransaction(SignatureAlgorithmFactory.getInstance().generateKeyPair()),
                    Optional.of(Wei.ONE),
                    Optional.empty(),
                    TransactionValidationParams.transactionPool())
                .isValid())
        .isTrue();
  }

  /** Accepting standard transactions does not enable the curve as a flexible DSA type. */
  @Test
  void withoutADsaProviderNoFlexibleTypeIsEnabledNotEvenTheCurve() {
    assertThatThrownBy(
            () ->
                DSAProviderFactory.getVerifierProvider()
                    .getAccountEnabledDSAById(DSAParametersSet.SECP256K1.getId()))
        .isInstanceOf(DsaNotEnabledException.class);
  }

  /** A flexible transaction of an enabled type does not admit a standard delegation inside it. */
  @Test
  void refusesAStandardDelegationWhenSecp256k1IsNotEnabled() throws Exception {
    final MainnetTransactionValidator validator = validatorEnabling(DSAParametersSet.MLDSA44);
    final org.hyperledger.besu.datatypes.CodeDelegation standardDelegation =
        CodeDelegation.builder()
            .chainId(CHAIN_ID)
            .address(DELEGATE)
            .nonce(0L)
            .signAndBuild(new SECP256K1().generateKeyPair());
    final KeyPair mlDsaSigner =
        new SupportedAlgorithms()
            .getDSAByName(DSAParametersSet.MLDSA44.getName())
            .get()
            .generateNodeKeyPair();

    final Transaction transaction =
        Transaction.builder()
            .type(TransactionType.FLEXIBLE_DELEGATE_CODE)
            .dsaType(DSAParametersSet.MLDSA44.getId())
            .chainId(CHAIN_ID)
            .nonce(0)
            .maxPriorityFeePerGas(Wei.of(1))
            .maxFeePerGas(Wei.of(2))
            .gasLimit(100_000)
            .to(DELEGATE)
            .value(Wei.ZERO)
            .payload(Bytes.EMPTY)
            .accessList(List.of())
            .codeDelegations(List.of(standardDelegation))
            .signAndBuild(mlDsaSigner);

    final ValidationResult<TransactionInvalidReason> result =
        validator.validate(
            transaction,
            Optional.of(Wei.ONE),
            Optional.empty(),
            TransactionValidationParams.transactionPool());

    assertThat(result.getInvalidReason()).isEqualTo(TransactionInvalidReason.INVALID_SIGNATURE);
    assertThat(result.getErrorMessage()).contains("SECP256K1");
  }

  /** Built after the provider is set: the validator takes it in its constructor. */
  private static MainnetTransactionValidator validatorEnabling(final DSAParametersSet... enabled)
      throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration config =
        new DigitalSignatureAlgorithmConfiguration();
    config.buildAccountSupportedAlgorithms(List.of(enabled));
    config.setNodeActiveDSA(DSAParametersSet.SECP256K1.getName());
    DSAProviderFactory.setDsaProvider(config, null);
    return validator();
  }

  private static MainnetTransactionValidator validator() {
    return new MainnetTransactionValidator(
        new PragueGasCalculator(),
        GasLimitCalculator.constant(),
        FeeMarket.london(0L),
        false,
        Optional.of(CHAIN_ID),
        Set.of(TransactionType.EIP1559, TransactionType.FLEXIBLE_DELEGATE_CODE),
        Set.of(BlobType.KZG_PROOF),
        Integer.MAX_VALUE);
  }

  private static Transaction standardTransaction(final KeyPair signer) {
    return Transaction.builder()
        .type(TransactionType.EIP1559)
        .chainId(CHAIN_ID)
        .nonce(0)
        .maxPriorityFeePerGas(Wei.of(1))
        .maxFeePerGas(Wei.of(2))
        .gasLimit(21_000)
        .to(DELEGATE)
        .value(Wei.of(1))
        .payload(Bytes.EMPTY)
        .signAndBuild(signer);
  }
}
