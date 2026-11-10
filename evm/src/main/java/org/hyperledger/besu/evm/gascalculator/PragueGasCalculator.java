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

import static org.hyperledger.besu.datatypes.Address.BLS12_MAP_FP2_TO_G2;
import static org.hyperledger.besu.evm.internal.Words.clampedAdd;
import static org.hyperledger.besu.evm.worldstate.CodeDelegationHelper.hasCodeDelegation;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.CodeDelegation;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Transaction;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.worldstate.CodeDelegationHelper;

import org.apache.tuweni.bytes.Bytes;

/**
 * Gas Calculator for Prague
 *
 * <UL>
 *   <LI>Gas costs for EIP-7702 (Code Delegation)
 * </UL>
 */
public class PragueGasCalculator extends CancunGasCalculator {
  private static final long TOTAL_COST_FLOOR_PER_TOKEN = 10L;

  final long existingAccountGasRefund;

  /** Instantiates a new Prague Gas Calculator. */
  public PragueGasCalculator() {
    this(BLS12_MAP_FP2_TO_G2.getBytes().toArrayUnsafe()[19]);
  }

  /**
   * Instantiates a new Prague Gas Calculator
   *
   * @param maxPrecompile the max precompile
   */
  protected PragueGasCalculator(final int maxPrecompile) {
    super(maxPrecompile);
    this.existingAccountGasRefund = newAccountGasCost() - CodeDelegation.PER_AUTH_BASE_COST;
  }

  /**
   * A transaction that carries a dsaType pays the base cost of that DSA type in place of the 21,000
   * of a transaction signed with r, s and v. Any other transaction pays 21,000.
   */
  @Override
  protected long transactionBaseCost(final Transaction transaction) {
    return transaction
        .getDsaType()
        .map(dsaTypeId -> dsaBaseCost(dsaTypeId.shortValue()))
        .orElseGet(() -> super.transactionBaseCost(transaction));
  }

  /**
   * Returns the base cost of the DSA type with this id, or {@link Long#MAX_VALUE}, which no gas
   * limit covers, for an id that is not a DSA type. Decoding already rejects such an id, so this
   * only keeps block processing from throwing on one.
   *
   * @param dsaTypeId the id of the DSA type
   * @return the base cost of a transaction signed with it
   */
  protected long dsaBaseCost(final short dsaTypeId) {
    final DSAParametersSet dsaType;
    try {
      dsaType = DSAParametersSet.fromId(dsaTypeId);
    } catch (final IllegalArgumentException e) {
      return Long.MAX_VALUE;
    }
    return dsaBaseCost(dsaType);
  }

  /**
   * Returns the base cost of a transaction signed with this DSA type: the 21,000 of a standard
   * transaction, with its secp256k1 signature replaced by one of this DSA type.
   *
   * <pre>
   * base cost = 21,000 - 3,000 - 65 x 16 + CPU gas + 16 x (signature bytes + key bytes)
   * </pre>
   *
   * <p>The 3,000 is the ECRECOVER price of the secp256k1 key recovery that 21,000 already pays for,
   * and 65 x 16 the calldata price of its r, s and v. CPU gas is what authenticating this signature
   * costs relative to that recovery (a key recovery for recoverable algorithms, a verification for
   * the others, each half by its own rule for hybrids), anchored at the same 3,000. The signature
   * is priced at its maximum length, the key only when it cannot be recovered from the signature,
   * and every byte as a non-zero calldata byte, so the cost is known before the transaction is
   * signed.
   *
   * <p>The values come from {@code SignatureGasReport} in crypto/algorithms (run on 2026-11-06,
   * native secp256k1, 3 forks of 10 iterations). SECP256K1 closes at exactly 21,000, the price of a
   * standard transaction. A switch with no default, so a new DSA type does not compile until it is
   * priced.
   *
   * @param dsaType the DSA type
   * @return the base cost of a transaction signed with it
   */
  protected long dsaBaseCost(final DSAParametersSet dsaType) {
    return switch (dsaType) {
      case SECP256K1 -> 21_000L;
      case SECP256R1 -> 31_629L;
      case MLDSA44 -> 82_553L;
      case MLDSA65 -> 110_047L;
      case MLDSA87 -> 147_047L;
      case FALCON512 -> 46_511L;
      case SECP256K1MLDSA44 -> 86_102L;
      case SECP256K1FALCON512 -> 50_369L;
    };
  }

  @Override
  public long delegateCodeGasCost(final int delegateCodeListLength) {
    return newAccountGasCost() * delegateCodeListLength;
  }

  @Override
  public long calculateDelegateCodeGasRefund(final long alreadyExistingAccounts) {
    return existingAccountGasRefund * alreadyExistingAccounts;
  }

  @Override
  public long calculateGasRefund(
      final Transaction transaction,
      final MessageFrame initialFrame,
      final long codeDelegationRefund) {

    final long refundAllowance =
        calculateRefundAllowance(transaction, initialFrame, codeDelegationRefund);

    final long executionGasUsed =
        transaction.getGasLimit() - initialFrame.getRemainingGas() - refundAllowance;
    final long transactionFloorCost = transactionFloorCost(transaction);
    final long totalGasUsed = Math.max(executionGasUsed, transactionFloorCost);
    return transaction.getGasLimit() - totalGasUsed;
  }

  private long calculateRefundAllowance(
      final Transaction transaction,
      final MessageFrame initialFrame,
      final long codeDelegationRefund) {
    final long selfDestructRefund =
        getSelfDestructRefundAmount() * initialFrame.getSelfDestructs().size();
    final long executionRefund =
        initialFrame.getGasRefund() + selfDestructRefund + codeDelegationRefund;
    // Integer truncation takes care of the floor calculation needed after the divide.
    final long maxRefundAllowance =
        (transaction.getGasLimit() - initialFrame.getRemainingGas()) / getMaxRefundQuotient();
    return Math.min(executionRefund, maxRefundAllowance);
  }

  @Override
  public long transactionFloorCost(final Bytes transactionPayload, final long payloadZeroBytes) {
    return floorCost(getMinimumTransactionCost(), transactionPayload, payloadZeroBytes);
  }

  /**
   * The floor starts from the base cost of the transaction, not from 21,000, so a flexible
   * transaction with a large payload still pays for its signature: its signature and key bytes stay
   * priced at 16 gas each, within that base cost, and only the payload is priced as floor tokens.
   */
  @Override
  public long transactionFloorCost(final Transaction transaction) {
    return floorCost(
        transactionBaseCost(transaction),
        transaction.getPayload(),
        transaction.getPayloadZeroBytes());
  }

  private long floorCost(
      final long baseCost, final Bytes transactionPayload, final long payloadZeroBytes) {
    return clampedAdd(
        baseCost,
        tokensInCallData(transactionPayload.size(), payloadZeroBytes) * TOTAL_COST_FLOOR_PER_TOKEN);
  }

  private long tokensInCallData(final long payloadSize, final long zeroBytes) {
    // as defined in https://eips.ethereum.org/EIPS/eip-7623#specification
    return clampedAdd(zeroBytes, (payloadSize - zeroBytes) * 4);
  }

  @Override
  public long calculateCodeDelegationResolutionGas(
      final MessageFrame frame, final Account targetAccount) {
    if (targetAccount == null) {
      return 0;
    }

    final Hash codeHash = targetAccount.getCodeHash();
    if (codeHash == null || codeHash.equals(Hash.EMPTY)) {
      return 0;
    }

    if (!hasCodeDelegation(targetAccount.getCode())) {
      return 0;
    }

    final Address targetAddress = CodeDelegationHelper.getTargetAddress(targetAccount.getCode());

    final boolean isWarm = isPrecompile(targetAddress) || frame.warmUpAddress(targetAddress);
    return isWarm ? getWarmStorageReadCost() : getColdAccountAccessCost();
  }
}
