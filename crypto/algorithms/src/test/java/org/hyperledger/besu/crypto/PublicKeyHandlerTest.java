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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.key.PublicKeyHandler;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.hyperledger.besu.crypto.signature.SignatureFactory;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

/**
 * The RLPx and DiscV5 handshakes are classical whatever the node's DSA, so they need the secp256k1
 * half of a possibly hybrid key. Resolving a signer's key recovers every half that can be
 * recovered, since verifying a hybrid signature leaves that half to recovery.
 */
class PublicKeyHandlerTest {

  private static final Bytes32 HASH = Hash.keccak256(Bytes.fromHexString("0xc0ffee"));

  private final DigitalSignatureAlgorithm hybrid =
      new SupportedAlgorithms().getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName()).get();

  @Test
  void resolvesTheSignerFromTheHalfThatCannotBeRecovered() {
    final KeyPair signer = hybrid.generateNodeKeyPair();
    final Signature signature = hybrid.sign(HASH, signer.getPrivateKey());
    final PublicKey mlDsaHalf = ((CompositePublicKey) signer.getPublicKey()).getSecondKey();

    final PublicKey resolved =
        PublicKeyHandler.resolvePublicKey(hybrid, signature, Optional.of(mlDsaHalf), HASH, "test")
            .orElseThrow();

    assertThat(resolved.getEncoded()).isEqualTo(signer.getPublicKey().getEncoded());
  }

  @Test
  void resolvesTheSameSignerFromAWholeCompositeKey() {
    final KeyPair signer = hybrid.generateNodeKeyPair();
    final Signature signature = hybrid.sign(HASH, signer.getPrivateKey());

    final PublicKey resolved =
        PublicKeyHandler.resolvePublicKey(
                hybrid, signature, Optional.of(signer.getPublicKey()), HASH, "test")
            .orElseThrow();

    assertThat(resolved.getEncoded()).isEqualTo(signer.getPublicKey().getEncoded());
  }

  /**
   * The attack: an attacker holding only a victim's ML-DSA-44 key signs the classical half with a
   * key of their own, re-signs the ML-DSA half over it so the nesting lines up, and hands in the
   * victim's whole composite key. The hybrid DSA accepts that signature, because it leaves the
   * classical half to recovery, so the classical half has to be recovered rather than taken from
   * the stated key: that resolves to the attacker's classical key, not the victim's.
   */
  @Test
  void recoversTheClassicalHalfInsteadOfTakingItFromAStatedCompositeKey() {
    final KeyPair victim = hybrid.generateNodeKeyPair();
    final KeyPair attacker = hybrid.generateNodeKeyPair();
    final DigitalSignatureAlgorithm mldsa =
        new SupportedAlgorithms().getDSAByName(DSAParametersSet.MLDSA44.getName()).get();

    final Signature foreignEcdsa =
        SignatureAlgorithmFactory.getInstance()
            .sign(HASH, ((CompositePrivateKey) attacker.getPrivateKey()).getFirstKey());
    final Signature victimMlDsa =
        mldsa.sign(
            Bytes.concatenate(HASH, foreignEcdsa.encodedBytes()),
            ((CompositePrivateKey) victim.getPrivateKey()).getSecondKey());
    final Signature forged =
        SignatureFactory.createCompositeConcSignature(foreignEcdsa, victimMlDsa);

    assertThat(hybrid.verify(HASH, forged, victim.getPublicKey())).isTrue();

    final CompositePublicKey resolved =
        (CompositePublicKey)
            PublicKeyHandler.resolvePublicKey(
                    hybrid, forged, Optional.of(victim.getPublicKey()), HASH, "test")
                .orElseThrow();

    assertThat(resolved.getEncoded()).isNotEqualTo(victim.getPublicKey().getEncoded());
    assertThat(resolved.getFirstKey().getEncoded())
        .isEqualTo(((CompositePublicKey) attacker.getPublicKey()).getFirstKey().getEncoded());
  }

  @Test
  void takesTheClassicalHalfOfAHybridKey() {
    final CompositePublicKey hybridKey =
        (CompositePublicKey)
            new SupportedAlgorithms()
                .getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName())
                .get()
                .generateNodeKeyPair()
                .getPublicKey();

    final SECPPublicKey classicalKey = PublicKeyHandler.secp256k1(hybridKey);

    assertThat(classicalKey.getEncoded()).isEqualTo(hybridKey.getFirstKey().getEncoded());
  }

  @Test
  void returnsAClassicalKeyUnchanged() {
    final SECPPublicKey publicKey =
        (SECPPublicKey) SignatureAlgorithmFactory.getInstance().generateKeyPair().getPublicKey();

    assertThat(PublicKeyHandler.secp256k1(publicKey)).isSameAs(publicKey);
  }

  @Test
  void rejectsAKeyWithNoClassicalHalf() {
    final MLDSAPublicKey mldsaKey =
        (MLDSAPublicKey)
            new SupportedAlgorithms()
                .getDSAByName(DSAParametersSet.MLDSA44.getName())
                .get()
                .generateNodeKeyPair()
                .getPublicKey();

    assertThatThrownBy(() -> PublicKeyHandler.secp256k1(mldsaKey))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("secp256k1");
  }

  @Test
  void rejectsAHybridKeyWhoseFirstHalfIsNotClassical() {
    final var mldsa =
        new SupportedAlgorithms().getDSAByName(DSAParametersSet.MLDSA44.getName()).get();
    final CompositePublicKey reversed =
        CompositePublicKey.create(
            mldsa.generateNodeKeyPair().getPublicKey(),
            SignatureAlgorithmFactory.getInstance().generateKeyPair().getPublicKey());

    assertThatThrownBy(() -> PublicKeyHandler.secp256k1(reversed))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void theClassicalHalfIsTheLeadingBytesOfTheEncoding() {
    final CompositePublicKey hybridKey =
        (CompositePublicKey)
            new SupportedAlgorithms()
                .getDSAByName(DSAParametersSet.SECP256K1MLDSA44.getName())
                .get()
                .generateNodeKeyPair()
                .getPublicKey();

    // the node id layout the vnt scheme and the enode both rely on
    assertThat(Bytes.wrap(PublicKeyHandler.secp256k1(hybridKey).getEncoded()))
        .isEqualTo(
            Bytes.wrap(hybridKey.getEncoded())
                .slice(0, DSAParametersSet.SECP256K1.getPublicKeyLength()));
  }

  @Test
  void aSignatureFromWhichNoKeyCanBeRecoveredIsRejectedAsBadInput() {
    // As secp256r1's native library answers a signature with no signer on the curve.
    final SECP256R1 noSigner =
        new SECP256R1() {
          @Override
          protected BigInteger recoverFromSignature(
              final int recId, final BigInteger r, final BigInteger s, final Bytes32 dataHash) {
            return null;
          }
        };
    // The native library recovers without going through the override, where it is available.
    noSigner.disableNative();
    final SECP256R1 signer = new SECP256R1();
    final Signature signature = signer.sign(HASH, signer.generateNodeKeyPair().getPrivateKey());

    assertThatThrownBy(
            () -> PublicKeyHandler.resolvePublicKey(noSigner, signature, Optional.empty(), HASH, "test"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Cannot recover public key");
  }

  @Test
  void aNonRecoverableSignatureWithoutItsKeyIsRejectedAsBadInput() {
    final DigitalSignatureAlgorithm mlDsa =
        new SupportedAlgorithms().getDSAByName(DSAParametersSet.MLDSA44.getName()).get();
    final Signature signature = mlDsa.sign(HASH, mlDsa.generateNodeKeyPair().getPrivateKey());

    assertThatThrownBy(
            () -> PublicKeyHandler.resolvePublicKey(mlDsa, signature, Optional.empty(), HASH, "test"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Public key must be provided when algorithm does not support PKR");
  }
}
