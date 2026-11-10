/*
 * Copyright contributors to Hyperledger Besu.
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
package org.hyperledger.besu.evm.gascalculator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Transaction;
import org.hyperledger.besu.evm.frame.MessageFrame;

import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.apache.tuweni.bytes.Bytes;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class PragueGasCalculatorTest {

  private final PragueGasCalculator pragueGasCalculator = new PragueGasCalculator();
  @Mock private Transaction transaction;
  @Mock private MessageFrame messageFrame;

  @Test
  void testPrecompileSize() {
    PragueGasCalculator subject = new PragueGasCalculator();
    assertThat(subject.isPrecompile(Address.precompiled(0x12))).isFalse();
    assertThat(subject.isPrecompile(Address.BLS12_MAP_FP2_TO_G2)).isTrue();
  }

  @Test
  void shouldCalculateRefundWithCodeDelegationAndNoSelfDestructs() {
    // Arrange
    when(messageFrame.getSelfDestructs()).thenReturn(Collections.emptySet());
    when(messageFrame.getGasRefund()).thenReturn(1000L);
    when(messageFrame.getRemainingGas()).thenReturn(5000L);
    when(transaction.getGasLimit()).thenReturn(100000L);
    when(transaction.getPayload()).thenReturn(Bytes.EMPTY);

    // Act
    long refund = pragueGasCalculator.calculateGasRefund(transaction, messageFrame, 500L);

    // Assert
    // execution refund = 1000 + 0 (self destructs) + 500 (code delegation) = 1500
    AssertionsForClassTypes.assertThat(refund)
        .isEqualTo(6500L); // 5000 (remaining) + min(1500 (execution refund), 19000 (max allowance))
  }

  @Test
  void shouldCalculateRefundWithMultipleSelfDestructs() {
    // Arrange
    Set<Address> selfDestructs = new HashSet<>();
    selfDestructs.add(Address.wrap(Bytes.random(20)));
    selfDestructs.add(Address.wrap(Bytes.random(20)));

    when(messageFrame.getSelfDestructs()).thenReturn(selfDestructs);
    when(messageFrame.getGasRefund()).thenReturn(1000L);
    when(messageFrame.getRemainingGas()).thenReturn(5000L);
    when(transaction.getGasLimit()).thenReturn(100000L);
    when(transaction.getPayload()).thenReturn(Bytes.EMPTY);

    // Act
    long refund = pragueGasCalculator.calculateGasRefund(transaction, messageFrame, 1000L);

    // Assert
    // execution refund = 1000 + 0 (self destructs EIP-3529) + 1000 (code delegation) = 2000
    AssertionsForClassTypes.assertThat(refund)
        .isEqualTo(7000L); // 5000 (remaining) + min(2000 (execution refund), 1900 (max allowance))
  }

  @Test
  void shouldRespectMaxRefundAllowance() {
    // Arrange
    when(messageFrame.getSelfDestructs()).thenReturn(Collections.emptySet());
    when(messageFrame.getGasRefund()).thenReturn(100000L);
    when(messageFrame.getRemainingGas()).thenReturn(20000L);
    when(transaction.getGasLimit()).thenReturn(100000L);
    when(transaction.getPayload()).thenReturn(Bytes.EMPTY);

    // Act
    long refund = pragueGasCalculator.calculateGasRefund(transaction, messageFrame, 1000L);

    // Assert
    // execution refund = 100000 + 1000 (code delegation) = 101000
    AssertionsForClassTypes.assertThat(refund)
        .isEqualTo(
            36000L); // 20000 (remaining) + min(101000 (execution refund), 16000 (max allowance))
  }

  @Test
  void shouldHandleZeroValuesCorrectly() {
    // Arrange
    when(messageFrame.getSelfDestructs()).thenReturn(Collections.emptySet());
    when(messageFrame.getGasRefund()).thenReturn(0L);
    when(messageFrame.getRemainingGas()).thenReturn(0L);
    when(transaction.getGasLimit()).thenReturn(100000L);
    when(transaction.getPayload()).thenReturn(Bytes.EMPTY);

    // Act
    long refund =
        pragueGasCalculator.calculateGasRefund(
            transaction,
            messageFrame,
            0L); // 0 (remaining) + min(0 (execution refund), 20000 (max allowance))

    // Assert
    AssertionsForClassTypes.assertThat(refund).isEqualTo(0L);
  }

  @Test
  void shouldRespectTransactionFloorCost() {
    // Arrange
    when(messageFrame.getSelfDestructs()).thenReturn(Collections.emptySet());
    when(messageFrame.getGasRefund()).thenReturn(100000L);
    when(messageFrame.getRemainingGas()).thenReturn(90000L);
    when(transaction.getGasLimit()).thenReturn(100000L);
    when(transaction.getPayload()).thenReturn(Bytes.EMPTY);

    // Act
    long refund = pragueGasCalculator.calculateGasRefund(transaction, messageFrame, 1000L);

    // Assert
    // refund allowance = 16000
    // execution gas used = 100000 (gas limit) - 20000 (remaining gas) - 16000 (refund allowance) =
    // 64000
    // floor cost = 21000 (base cost) + 0 (tokensInCallData * floor cost per token) = 21000
    AssertionsForClassTypes.assertThat(refund)
        .isEqualTo(
            79000L); // 100000 (gas limit) - max(8000 (execution gas used), 21000 (floor cost))
  }

  @Test
  void transactionFloorCostShouldBeAtLeastTransactionBaseCost() {
    // floor cost = 21000 (base cost) + 0
    AssertionsForClassTypes.assertThat(pragueGasCalculator.transactionFloorCost(Bytes.EMPTY, 0))
        .isEqualTo(21000);
    // floor cost = 21000 (base cost) + 256 (tokensInCallData) * 10 (cost per token)
    AssertionsForClassTypes.assertThat(
            pragueGasCalculator.transactionFloorCost(Bytes.repeat((byte) 0x0, 256), 256))
        .isEqualTo(23560L);
    // floor cost = 21000 (base cost) + 256 * 4 (tokensInCallData) * 10 (cost per token)
    AssertionsForClassTypes.assertThat(
            pragueGasCalculator.transactionFloorCost(Bytes.repeat((byte) 0x1, 256), 0))
        .isEqualTo(31240L);
    // floor cost = 21000 (base cost) + 5 + (6 * 4) (tokensInCallData) * 10 (cost per token)
    AssertionsForClassTypes.assertThat(
            pragueGasCalculator.transactionFloorCost(
                Bytes.fromHexString("0x0001000100010001000101"), 5))
        .isEqualTo(21290L);
  }

  @Test
  void standardTransactionPaysTheStandardBaseCost() {
    givenTransfer(Optional.empty(), Bytes.EMPTY);

    assertThat(pragueGasCalculator.transactionIntrinsicGasCost(transaction, 0L)).isEqualTo(21_000L);
  }

  @ParameterizedTest
  @CsvSource({
    "SECP256K1, 21000",
    "SECP256R1, 31629",
    "MLDSA44, 82553",
    "MLDSA65, 110047",
    "MLDSA87, 147047",
    "FALCON512, 46511",
    "SECP256K1MLDSA44, 86102",
    "SECP256K1FALCON512, 50369"
  })
  void flexibleTransactionPaysTheBaseCostOfItsDsaType(
      final DSAParametersSet dsaType, final long baseCost) {
    givenTransfer(Optional.of(dsaType.getId()), Bytes.EMPTY);

    assertThat(pragueGasCalculator.transactionIntrinsicGasCost(transaction, 0L))
        .isEqualTo(baseCost);
  }

  @ParameterizedTest
  @EnumSource(DSAParametersSet.class)
  void noDsaTypeIsCheaperThanTheSecp256k1SignatureOfAStandardTransaction(
      final DSAParametersSet dsaType) {
    assertThat(pragueGasCalculator.dsaBaseCost(dsaType))
        .isGreaterThanOrEqualTo(pragueGasCalculator.getMinimumTransactionCost());
  }

  @Test
  void flexibleTransactionPaysForItsPayloadAndAccessListOnTopOfItsBaseCost() {
    // 10 non-zero bytes at 16 gas, and 2,400 gas of access list passed as baseline gas
    givenTransfer(Optional.of(DSAParametersSet.MLDSA44.getId()), Bytes.repeat((byte) 0x1, 10));

    assertThat(pragueGasCalculator.transactionIntrinsicGasCost(transaction, 2_400L))
        .isEqualTo(82_553L + 160L + 2_400L);
  }

  @Test
  void flexibleTransactionWithAnUnknownDsaTypeCannotBePaidFor() {
    givenTransfer(Optional.of((short) 0x7fff), Bytes.EMPTY);

    assertThat(pragueGasCalculator.transactionIntrinsicGasCost(transaction, 0L))
        .isEqualTo(Long.MAX_VALUE);
  }

  @Test
  void osakaKeepsThePragueBaseCostOfFlexibleTransactions() {
    givenTransfer(Optional.of(DSAParametersSet.MLDSA44.getId()), Bytes.EMPTY);

    assertThat(new OsakaGasCalculator().transactionIntrinsicGasCost(transaction, 0L))
        .isEqualTo(82_553L);
  }

  @Test
  void floorOfAFlexibleTransactionStartsFromTheBaseCostOfItsDsaType() {
    // 10,000 non-zero bytes = 40,000 tokens at 10 gas; the signature stays within the base cost
    givenTransfer(Optional.of(DSAParametersSet.MLDSA44.getId()), Bytes.repeat((byte) 0x1, 10_000));

    assertThat(pragueGasCalculator.transactionFloorCost(transaction)).isEqualTo(82_553L + 400_000L);
  }

  @Test
  void floorOfAStandardTransactionStillStartsFrom21000() {
    givenTransfer(Optional.empty(), Bytes.repeat((byte) 0x1, 256));

    assertThat(pragueGasCalculator.transactionFloorCost(transaction))
        .isEqualTo(pragueGasCalculator.transactionFloorCost(Bytes.repeat((byte) 0x1, 256), 0))
        .isEqualTo(31_240L);
  }

  @Test
  void refundOfAFlexibleTransactionKeepsItsFloor() {
    // execution used 242,553 (intrinsic only) of a 600,000 limit; the floor is 482,553
    givenTransfer(Optional.of(DSAParametersSet.MLDSA44.getId()), Bytes.repeat((byte) 0x1, 10_000));
    when(transaction.getGasLimit()).thenReturn(600_000L);
    when(messageFrame.getSelfDestructs()).thenReturn(Collections.emptySet());
    when(messageFrame.getGasRefund()).thenReturn(0L);
    when(messageFrame.getRemainingGas()).thenReturn(600_000L - 242_553L);

    assertThat(pragueGasCalculator.calculateGasRefund(transaction, messageFrame, 0L))
        .isEqualTo(600_000L - 482_553L);
  }

  private void givenTransfer(final Optional<Short> dsaType, final Bytes payload) {
    when(transaction.getDsaType()).thenReturn(dsaType);
    when(transaction.getPayload()).thenReturn(payload);
    when(transaction.getPayloadZeroBytes()).thenReturn(0L);
    // the intrinsic gas reads it, the floor does not
    lenient().when(transaction.isContractCreation()).thenReturn(false);
  }
}
