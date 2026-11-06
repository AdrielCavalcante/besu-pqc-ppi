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
package org.hyperledger.besu.ethereum.core.encoding;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.ethereum.core.Transaction;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A FLEXIBLE_EIP1559 transaction signed with ML-DSA-44, a non-hybrid algorithm that carries its
 * whole public key, taken through the same encode, decode and verify steps the network applies.
 *
 * <p>The wrong-length cases are the ones that used to escape as an internal error: a 100-byte key
 * reached BouncyCastle, which failed with an ArrayIndexOutOfBoundsException while unpacking it, and
 * {@code eth_sendRawTransaction} answered {@code -32603 Internal error}.
 */
class FlexibleEIP1559MLDSA44TransactionTest {

  private static final short MLDSA44_ID = DSAParametersSet.MLDSA44.getId();

  private final MLDSA mldsa = new MLDSA(DSAParametersSet.MLDSA44);

  @BeforeEach
  void setUp() throws InvalidAlgorithmParameterException {
    final DigitalSignatureAlgorithmConfiguration dsaConfig =
        new DigitalSignatureAlgorithmConfiguration();
    dsaConfig.setNodeActiveDSA(DSAParametersSet.SECP256K1.getName());
    dsaConfig.buildAccountSupportedAlgorithms(
        List.of(DSAParametersSet.SECP256K1, DSAParametersSet.MLDSA44));
    DSAProviderFactory.setDsaProvider(dsaConfig, null);
  }

  @AfterEach
  void tearDown() {
    DSAProviderFactory.resetDsaProvider();
  }

  @Test
  void mldsaTransactionSurvivesTheWireAndVerifies() {
    final KeyPair keyPair = mldsa.generateNodeKeyPair();
    final Transaction signed = sign(keyPair, Wei.of(1_000));

    final Transaction decoded = roundTrip(signed);

    assertThat(decoded.getType()).isEqualTo(TransactionType.FLEXIBLE_EIP1559);
    assertThat(decoded.getDsaType()).contains(MLDSA44_ID);
    assertThat(decoded.getMountedPublicKey().getEncoded())
        .isEqualTo(keyPair.getPublicKey().getEncoded());
    assertThat(decoded.getSender()).isEqualTo(Address.extract(keyPair.getPublicKey()));
    assertThat(verifyAsTheValidatorDoes(decoded)).isTrue();
  }

  @Test
  void aPublicKeyOfTheWrongLengthIsRefusedWhenTheTransactionIsDecoded() {
    final KeyPair keyPair = mldsa.generateNodeKeyPair();
    final Transaction signed = sign(keyPair, Wei.of(1_000));

    // Same signature, but the carried key is 100 bytes instead of 1312.
    final Transaction withShortKey =
        unsigned(keyOfLength(100), Wei.of(1_000)).signature(signed.getSignature()).build();
    final Bytes wire =
        TransactionEncoder.encodeOpaqueBytes(withShortKey, EncodingContext.BLOCK_BODY);

    // The same rejection a hybrid transaction with a short key already gets, which
    // eth_sendRawTransaction reports as -32602 Invalid params.
    assertThatThrownBy(() -> TransactionDecoder.decodeOpaqueBytes(wire, EncodingContext.BLOCK_BODY))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("MLDSA44 public key of 1312 bytes, got 100");
  }

  @Test
  void aPublicKeyOfTheWrongLengthFailsVerificationInsteadOfThrowing() {
    final KeyPair keyPair = mldsa.generateNodeKeyPair();
    final Transaction signed = sign(keyPair, Wei.of(1_000));

    // The call MainnetTransactionValidator makes, with a key that never went through decoding.
    final DigitalSignatureAlgorithm dsa =
        DSAProviderFactory.getVerifierProvider().getAccountEnabledDSAById(MLDSA44_ID);
    assertThat(
            dsa.verify(
                Bytes.wrap(signed.getSigningHash()), signed.getSignature(), keyOfLength(100)))
        .isFalse();
  }

  private static Transaction sign(final KeyPair keyPair, final Wei value) {
    return unsigned(keyPair.getPublicKey(), value).signAndBuild(keyPair);
  }

  private static Transaction.Builder unsigned(final PublicKey publicKey, final Wei value) {
    return Transaction.builder()
        .type(TransactionType.FLEXIBLE_EIP1559)
        .dsaType(MLDSA44_ID)
        .chainId(BigInteger.valueOf(1337))
        .nonce(7)
        .maxPriorityFeePerGas(Wei.of(1))
        .maxFeePerGas(Wei.of(2))
        .gasLimit(21_000)
        .to(Address.fromHexString("0x000000000000000000000000000000000000beef"))
        .value(value)
        .payload(Bytes.EMPTY)
        .accessList(List.of())
        .providedPublicKey(Optional.of(publicKey));
  }

  private static Transaction roundTrip(final Transaction transaction) {
    return TransactionDecoder.decodeOpaqueBytes(
        TransactionEncoder.encodeOpaqueBytes(transaction, EncodingContext.BLOCK_BODY),
        EncodingContext.BLOCK_BODY);
  }

  private static boolean verifyAsTheValidatorDoes(final Transaction transaction) {
    final DigitalSignatureAlgorithm dsa =
        DSAProviderFactory.getVerifierProvider()
            .getAccountEnabledDSAById(transaction.getDsaType().orElseThrow());
    return dsa.verify(
        Bytes.wrap(transaction.getSigningHash()),
        transaction.getSignature(),
        transaction.getMountedPublicKey());
  }

  /** A key of the given length, which MLDSAPublicKey.create would refuse to build. */
  private static PublicKey keyOfLength(final int length) {
    return new PublicKey() {
      private static final long serialVersionUID = 1L;

      @Override
      public String getAlgorithm() {
        return DSAParametersSet.MLDSA44.getName();
      }

      @Override
      public String getFormat() {
        return "RAW";
      }

      @Override
      public byte[] getEncoded() {
        return new byte[length];
      }
    };
  }
}
