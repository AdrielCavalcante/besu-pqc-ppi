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
package org.hyperledger.besu.crypto.key;

import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SECPCurves;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.key.types.FalconPrivateKey;
import org.hyperledger.besu.crypto.key.types.FalconPublicKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPrivateKey;
import org.hyperledger.besu.crypto.key.types.MLDSAPublicKey;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

public class KeyFactory {
  private static final KeyExtractor keyExtractor = new KeyExtractor();

  private KeyFactory() {}

  public static PrivateKey createPrivateKey(
      final Bytes privateKeyBytes,
      final DSAParametersSet paramsSet,
      final PrivateKeyRepresentation firstSkRep,
      final PrivateKeyRepresentation secondSkRep) {
    PrivateKey sk;
    switch (paramsSet) {
      case SECP256K1:
      case SECP256R1:
        sk = SECPPrivateKey.create(Bytes32.wrap(privateKeyBytes), paramsSet.getName());
        break;
      case MLDSA44:
      case MLDSA65:
      case MLDSA87:
        sk = MLDSAPrivateKey.create(privateKeyBytes, paramsSet);
        break;
            case FALCON512:
                sk = FalconPrivateKey.create(privateKeyBytes, paramsSet);
                break;
      case SECP256K1MLDSA44:
        // Both halves have a fixed length, so the whole key has one too. Checked up front, as
        // for SECP256K1-FALCON512, instead of failing on an out-of-bounds slice below.
        final int expectedSkLength =
            keyExtractor.privateKeyLength(DSAParametersSet.SECP256K1, firstSkRep)
                + keyExtractor.privateKeyLength(DSAParametersSet.MLDSA44, secondSkRep);
        if (privateKeyBytes.size() != expectedSkLength) {
          throw new IllegalArgumentException(
              "SECP256K1-MLDSA44 private key must be "
                  + expectedSkLength
                  + " bytes, got "
                  + privateKeyBytes.size());
        }
        Bytes secpSkBytes =
            keyExtractor.extractPrivateKeyBytesAtOffset(
                privateKeyBytes, 0, DSAParametersSet.SECP256K1, firstSkRep);
        PrivateKey secpSk =
            createPrivateKey(
                secpSkBytes, DSAParametersSet.SECP256K1, PrivateKeyRepresentation.EXPANDED, null);

        Bytes mldsaSk44Bytes =
            keyExtractor.extractPrivateKeyBytesAtOffset(
                privateKeyBytes,
                DSAParametersSet.SECP256K1.getPrivateKeyLength(),
                DSAParametersSet.MLDSA44,
                secondSkRep);
        PrivateKey mldsaSk44 =
            createPrivateKey(
                mldsaSk44Bytes, DSAParametersSet.MLDSA44, PrivateKeyRepresentation.EXPANDED, null);

                sk = CompositePrivateKey.create(secpSk, mldsaSk44);
                break;
            case SECP256K1FALCON512: {
                // Both halves are fixed-length: SECP256K1 || Falcon-512 (f || g || F || h).
                final int secpSkLength = DSAParametersSet.SECP256K1.getPrivateKeyLength();
                final int falconSkLength = DSAParametersSet.FALCON512.getPrivateKeyLength();
                if (privateKeyBytes.size() != secpSkLength + falconSkLength) {
                    throw new IllegalArgumentException(
                        "SECP256K1-FALCON512 private key must be "
                            + (secpSkLength + falconSkLength)
                            + " bytes, got "
                            + privateKeyBytes.size());
                }
                sk =
                    CompositePrivateKey.create(
                        createPrivateKey(
                            privateKeyBytes.slice(0, secpSkLength),
                            DSAParametersSet.SECP256K1,
                            PrivateKeyRepresentation.EXPANDED,
                            null),
                        FalconPrivateKey.create(
                            privateKeyBytes.slice(secpSkLength), DSAParametersSet.FALCON512));
                break;
            }
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }
        return sk;
    }

  public static PublicKey createPublicKey(
      final PrivateKey privateKey, final DSAParametersSet paramsSet) {
    PublicKey pk;
    switch (paramsSet) {
      case SECP256K1:
      case SECP256R1:
        SECPPrivateKey secpSk = (SECPPrivateKey) privateKey;
        pk = SECPCurves.of(paramsSet).createPublicKey(secpSk);
        break;
      case MLDSA44:
      case MLDSA65:
      case MLDSA87:
        pk = MLDSAPublicKey.create(privateKey, paramsSet);
        break;
        case FALCON512:
                pk = FalconPublicKey.create(privateKey);
                break;
      case SECP256K1MLDSA44:
        CompositePrivateKey compositeSk = (CompositePrivateKey) privateKey;

        PrivateKey secpFirstSk = compositeSk.getFirstKey();
        PrivateKey mldsaSecondSk = compositeSk.getSecondKey();

        PublicKey secpFirstPk = createPublicKey(secpFirstSk, DSAParametersSet.SECP256K1);
        PublicKey mldsaSecondPk = createPublicKey(mldsaSecondSk, DSAParametersSet.MLDSA44);

                pk = CompositePublicKey.create(secpFirstPk, mldsaSecondPk);
                break;
            case SECP256K1FALCON512: {
                final CompositePrivateKey hybridSk = (CompositePrivateKey) privateKey;
                pk =
                    CompositePublicKey.create(
                        createPublicKey(hybridSk.getFirstKey(), DSAParametersSet.SECP256K1),
                        createPublicKey(hybridSk.getSecondKey(), DSAParametersSet.FALCON512));
                break;
            }
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }
        return pk;
    }

  public static Optional<PublicKey> createPublicKey(
      final Bytes publicKeyBytes, final DSAParametersSet paramsSet) {
    PublicKey pk;
    switch (paramsSet) {
      case SECP256K1:
      case SECP256R1:
        pk = SECPPublicKey.create(publicKeyBytes, paramsSet.getName());
        break;
      case MLDSA44:
      case MLDSA65:
      case MLDSA87:
        pk = MLDSAPublicKey.create(publicKeyBytes, paramsSet);
        break;
        case FALCON512:
            pk = FalconPublicKey.create(publicKeyBytes, paramsSet);
            break;
      case SECP256K1MLDSA44:
        int expectedFullLength = DSAParametersSet.SECP256K1MLDSA44.getPublicKeyLength();

        if (publicKeyBytes.size() == expectedFullLength) {

          Bytes secpPkBytes =
              keyExtractor.extractPublicKeyBytesAtOffset(
                  publicKeyBytes, 0, DSAParametersSet.SECP256K1);

          Bytes mldsaPkBytes =
              keyExtractor.extractPublicKeyBytesAtOffset(
                  publicKeyBytes,
                  DSAParametersSet.SECP256K1.getPublicKeyLength(),
                  DSAParametersSet.MLDSA44);

          Optional<PublicKey> secpPk = createPublicKey(secpPkBytes, DSAParametersSet.SECP256K1);

          Optional<PublicKey> mldsaPk = createPublicKey(mldsaPkBytes, DSAParametersSet.MLDSA44);

                    return Optional.of(CompositePublicKey.create(secpPk.get(), mldsaPk.get()));
                }
                if(publicKeyBytes.size() == DSAParametersSet.MLDSA44.getPublicKeyLength()){
                    return Optional.of(MLDSAPublicKey.create(publicKeyBytes, DSAParametersSet.MLDSA44));
                }
                throw new IllegalArgumentException("Wrong public key size for: " + paramsSet.getName());
            case SECP256K1FALCON512: {
                final int secpPkLength = DSAParametersSet.SECP256K1.getPublicKeyLength();
                final int falconPkLength = DSAParametersSet.FALCON512.getPublicKeyLength();
                if (publicKeyBytes.size() == secpPkLength + falconPkLength) {
                    return Optional.of(
                        CompositePublicKey.create(
                            SECPPublicKey.create(
                                publicKeyBytes.slice(0, secpPkLength),
                                DSAParametersSet.SECP256K1.getName()),
                            FalconPublicKey.create(
                                publicKeyBytes.slice(secpPkLength), DSAParametersSet.FALCON512)));
                }
                // Transactions carry only the Falcon half: SECP256K1's is recovered from its signature.
                if (publicKeyBytes.size() == falconPkLength) {
                    return Optional.of(
                        FalconPublicKey.create(publicKeyBytes, DSAParametersSet.FALCON512));
                }
                throw new IllegalArgumentException(
                    "Wrong public key size for " + paramsSet.getName() + ": " + publicKeyBytes.size());
            }
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + paramsSet.getName());
        }
        return Optional.ofNullable(pk);
    }

  public static PublicKey createCompositePublicKey(
      final PublicKey firstPk, final PublicKey secondPk) {
    return CompositePublicKey.create(firstPk, secondPk);
  }

  public static KeyPair createKeyPair(final PrivateKey privateKey, final PublicKey publicKey) {
    return new KeyPair(privateKey, publicKey);
  }

  public static KeyPair createKeyPair(
      final Bytes privateKeyBytes, final Bytes publicKeyBytes, final DSAParametersSet dsaParams) {
    PrivateKey sk =
        createPrivateKey(
            privateKeyBytes,
            dsaParams,
            PrivateKeyRepresentation.EXPANDED,
            PrivateKeyRepresentation.EXPANDED);

    PublicKey pk = createPublicKey(sk, dsaParams);

    return createKeyPair(sk, pk);
  }

  public static KeyPair createHybridKeyPair(final KeyPair firstKp, final KeyPair secondKp) {
    PrivateKey hybridSk =
        CompositePrivateKey.create(firstKp.getPrivateKey(), secondKp.getPrivateKey());
    PublicKey hybridPk = CompositePublicKey.create(firstKp.getPublicKey(), secondKp.getPublicKey());

    return createKeyPair(hybridSk, hybridPk);
  }
}
