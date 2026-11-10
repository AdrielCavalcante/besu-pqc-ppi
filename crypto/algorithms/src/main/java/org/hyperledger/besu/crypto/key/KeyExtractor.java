package org.hyperledger.besu.crypto.key;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public class KeyExtractor {
    public Bytes extractPrivateKeyBytesAtOffset(
            final Bytes keyBytes,
            final Integer fromIndex,
            final DSAParametersSet params,
            final PrivateKeyRepresentation representation) {

        return keyBytes.slice(fromIndex, privateKeyLength(params, representation));
    }

    /** The length of a private key of {@code params} in the given representation. */
    public Integer privateKeyLength(
            final DSAParametersSet params, final PrivateKeyRepresentation representation) {
        switch (representation) {
            case EXPANDED:
                return params.getPrivateKeyLength();
            case SEED:
                return params.getSeedLength();
            default:
                throw new IllegalArgumentException("Unsupported private key representation: " + representation);
        }
    }

    public Bytes extractPublicKeyBytesAtOffset(
            final Bytes keyBytes,
            final Integer fromIndex,
            final DSAParametersSet params) {

        final Integer length = params.getPublicKeyLength();
        if (length == null || length <= 0) {
            throw new IllegalArgumentException("Public key length is invalid for " + params.getName());
        }

        return keyBytes.slice(fromIndex, length);
    }
}
