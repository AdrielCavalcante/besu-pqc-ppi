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
package org.hyperledger.besu.crypto;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Encoding and decoding of hybrid keys must agree on where one half ends and the other begins.
 *
 * <p>These halves are concatenated with no separator, which is what {@link DSAParametersSet}
 * declares, what {@code CompositePrivateKey} and {@code CompositePublicKey} write, and what the
 * composite signature decoder assumes.
 */
class CompositeKeyCodecTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;
  private static DigitalSignatureAlgorithm hybridAlgorithm;

  @BeforeAll
  static void setUp() {
    hybridAlgorithm = new SupportedAlgorithms().getDSAByName(HYBRID.getName()).get();
  }

  @Test
  void declaredLengthsAreTheSumOfTheHalves() {
    assertThat(HYBRID.getPrivateKeyLength())
        .isEqualTo(
            DSAParametersSet.SECP256K1.getPrivateKeyLength()
                + DSAParametersSet.MLDSA44.getPrivateKeyLength());
    assertThat(HYBRID.getPublicKeyLength())
        .isEqualTo(
            DSAParametersSet.SECP256K1.getPublicKeyLength()
                + DSAParametersSet.MLDSA44.getPublicKeyLength());
  }

  @Test
  void generatedKeysEncodeToTheDeclaredLengths() {
    final KeyPair keyPair = hybridAlgorithm.generateNodeKeyPair();

    assertThat(keyPair.getPrivateKey().getEncoded()).hasSize(HYBRID.getPrivateKeyLength());
    assertThat(keyPair.getPublicKey().getEncoded()).hasSize(HYBRID.getPublicKeyLength());
  }

  @Test
  void privateKeySurvivesEncodeThenDecode() {
    final KeyPair keyPair = hybridAlgorithm.generateNodeKeyPair();
    final CompositePrivateKey original = (CompositePrivateKey) keyPair.getPrivateKey();

    final CompositePrivateKey decoded = (CompositePrivateKey) decodePrivateKey(original);

    assertThat(decoded.getFirstKey().getEncoded()).isEqualTo(original.getFirstKey().getEncoded());
    assertThat(decoded.getSecondKey().getEncoded()).isEqualTo(original.getSecondKey().getEncoded());
  }

  @Test
  void publicKeySurvivesEncodeThenDecode() {
    final KeyPair keyPair = hybridAlgorithm.generateNodeKeyPair();
    final CompositePublicKey original = (CompositePublicKey) keyPair.getPublicKey();

    final PublicKey decoded =
        KeyFactory.createPublicKey(Bytes.wrap(original.getEncoded()), HYBRID).orElseThrow();

    assertThat(decoded).isInstanceOf(CompositePublicKey.class);
    assertThat(decoded.getEncoded()).isEqualTo(original.getEncoded());
  }

  @Test
  void publicKeyDerivedFromADecodedPrivateKeyMatchesTheOriginal() {
    final KeyPair keyPair = hybridAlgorithm.generateNodeKeyPair();

    final PrivateKey decoded = decodePrivateKey((CompositePrivateKey) keyPair.getPrivateKey());

    assertThat(KeyFactory.createPublicKey(decoded, HYBRID).getEncoded())
        .isEqualTo(keyPair.getPublicKey().getEncoded());
  }

  @Test
  void aDecodedPrivateKeySignsWhatTheOriginalPublicKeyVerifies() {
    final KeyPair keyPair = hybridAlgorithm.generateNodeKeyPair();
    final PrivateKey decoded = decodePrivateKey((CompositePrivateKey) keyPair.getPrivateKey());
    final Bytes message = Hash.keccak256(Bytes.wrap("a node record".getBytes(UTF_8)));

    final var signature = hybridAlgorithm.sign(message, decoded);

    assertThat(hybridAlgorithm.verify(message, signature, keyPair.getPublicKey())).isTrue();
  }

  @Test
  void aPublicKeyOfTheWrongSizeIsRejected() {
    final byte[] tooShort = new byte[HYBRID.getPublicKeyLength() - 1];

    assertThatThrownBy(() -> KeyFactory.createPublicKey(Bytes.wrap(tooShort), HYBRID))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void aPrivateKeyOfTheWrongSizeIsRejectedWithItsExpectedLength() {
    // A classical 32-byte key given to a hybrid node used to fail with "index is out of bounds".
    final byte[] classicalOnly = new byte[DSAParametersSet.SECP256K1.getPrivateKeyLength()];

    assertThatThrownBy(
            () ->
                KeyFactory.createPrivateKey(
                    Bytes.wrap(classicalOnly),
                    HYBRID,
                    PrivateKeyRepresentation.EXPANDED,
                    PrivateKeyRepresentation.EXPANDED))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(
            "SECP256K1-MLDSA44 private key must be "
                + HYBRID.getPrivateKeyLength()
                + " bytes, got "
                + classicalOnly.length);
  }

  /** Decodes a private key the same way the node does when it reads its key file. */
  private static PrivateKey decodePrivateKey(final CompositePrivateKey key) {
    return KeyFactory.createPrivateKey(
        Bytes.wrap(key.getEncoded()),
        HYBRID,
        PrivateKeyRepresentation.EXPANDED,
        PrivateKeyRepresentation.EXPANDED);
  }
}
