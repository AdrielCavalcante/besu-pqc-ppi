package org.hyperledger.besu.crypto;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.key.KeyFactory;
import org.hyperledger.besu.crypto.key.types.MLDSAPublicKey;
import org.hyperledger.besu.crypto.signature.Signature;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class MLDSATest {

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testGenerateNodeKeyPair(final DSAParametersSet params) {
        MLDSA mldsa = new MLDSA(params);
        KeyPair keyPair = mldsa.generateNodeKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivateKey());
        assertNotNull(keyPair.getPublicKey());
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testSignAndVerify(final DSAParametersSet params) {
        MLDSA mldsa = new MLDSA(params);
        KeyPair keyPair = mldsa.generateNodeKeyPair();

        PrivateKey sk = keyPair.getPrivateKey();
        PublicKey pk = keyPair.getPublicKey();

        Bytes message = Bytes.wrap("test message".getBytes(UTF_8));

        Signature signature = mldsa.sign(message, sk);
        assertNotNull(signature);

        boolean isValid = mldsa.verify(message, signature, pk);
        assertTrue(isValid, "Signature should be valid");
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testVerifyFailsForModifiedMessage(final DSAParametersSet params) {
        MLDSA mldsa = new MLDSA(params);
        KeyPair keyPair = mldsa.generateNodeKeyPair();

        PrivateKey sk = keyPair.getPrivateKey();
        PublicKey pk = keyPair.getPublicKey();

        Bytes message = Bytes.wrap("test message".getBytes(UTF_8));
        Bytes modified = Bytes.wrap("modified message".getBytes(UTF_8));

        Signature signature = mldsa.sign(message, sk);

        boolean isValid = mldsa.verify(modified, signature, pk);
        assertFalse(isValid, "Signature shouldn't be valid for a modified message");
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testGetDsaParametersSet(final DSAParametersSet params) {
        MLDSA mldsa = new MLDSA(params);
        assertEquals(params, mldsa.getDsaParametersSet());
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testVerifyFailsForKeyOfWrongLengthInsteadOfThrowing(final DSAParametersSet params) {
        MLDSA mldsa = new MLDSA(params);
        KeyPair keyPair = mldsa.generateNodeKeyPair();

        Bytes message = Bytes.wrap("test message".getBytes(UTF_8));
        Signature signature = mldsa.sign(message, keyPair.getPrivateKey());

        // A 100-byte key used to reach BouncyCastle, which failed with an
        // ArrayIndexOutOfBoundsException while unpacking it.
        PublicKey shortKey = keyOfLength(100, params);

        assertFalse(mldsa.verify(message, signature, shortKey), "A key of the wrong length should not verify");
    }

    @ParameterizedTest
    @EnumSource(value = DSAParametersSet.class, names = {"MLDSA44", "MLDSA65", "MLDSA87"})
    void testPublicKeyOfWrongLengthIsRefused(final DSAParametersSet params) {
        Bytes shortKey = Bytes.wrap(new byte[100]);

        IllegalArgumentException refused =
            assertThrows(IllegalArgumentException.class, () -> MLDSAPublicKey.create(shortKey, params));
        assertTrue(refused.getMessage().contains(String.valueOf(params.getPublicKeyLength())));
        assertThrows(IllegalArgumentException.class, () -> KeyFactory.createPublicKey(shortKey, params));
    }

    private static PublicKey keyOfLength(final int length, final DSAParametersSet params) {
        return new PublicKey() {
            private static final long serialVersionUID = 1L;

            @Override
            public String getAlgorithm() {
                return params.getName();
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
