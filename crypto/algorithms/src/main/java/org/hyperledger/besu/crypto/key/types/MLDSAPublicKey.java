package org.hyperledger.besu.crypto.key.types;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.hyperledger.besu.crypto.algorithms.MLDSA;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

public class MLDSAPublicKey implements PublicKey{
    private final String algorithmName;
    private final Bytes encoded;
    private final String format;

    public MLDSAPublicKey(final String algorithmName, final Bytes encoded, final String format){
        this.algorithmName = algorithmName;
        this.format = format;
        this.encoded = encoded;
    }

    @Override
    public String getAlgorithm(){
        return algorithmName;
    }

    @Override
    public String getFormat(){
        return format;
    }

    @Override
    public byte[] getEncoded(){
        return encoded.toArrayUnsafe();
    }

    /**
     * Builds an ML-DSA public key from its encoded bytes.
     *
     * <p>The length must be the one of the parameter set (1312, 1952 or 2592 bytes). BouncyCastle
     * unpacks the key at fixed offsets, so any other length fails deep inside verification, and the
     * bytes may come from an untrusted transaction; this is the one place where every key built
     * from bytes passes ({@code KeyFactory.createPublicKey} and, through it, the transaction, code
     * delegation and consensus decoders).
     *
     * @param pkBytes the encoded public key
     * @param dsaParametersSet the parameter set the key belongs to
     * @return the public key
     * @throws IllegalArgumentException if the length is not the one of the parameter set
     */
    public static MLDSAPublicKey create(final Bytes pkBytes, final DSAParametersSet dsaParametersSet){
        if (pkBytes.size() != dsaParametersSet.getPublicKeyLength()) {
            throw new IllegalArgumentException(
                "Expected a "
                    + dsaParametersSet.getName()
                    + " public key of "
                    + dsaParametersSet.getPublicKeyLength()
                    + " bytes, got "
                    + pkBytes.size());
        }
        return new MLDSAPublicKey(dsaParametersSet.getName(), pkBytes, "RAW");
    }

    public static MLDSAPublicKey create(final PrivateKey sk, final DSAParametersSet dsaParametersSet){
        MLDSAParameters mldsaParams = MLDSA.getBCMLDSAParametersByDSAParameterName(dsaParametersSet.getName());
        MLDSAPrivateKeyParameters skParams = new MLDSAPrivateKeyParameters(mldsaParams, sk.getEncoded());
        MLDSAPublicKeyParameters pkParams = skParams.getPublicKeyParameters();
        return create(Bytes.wrap(pkParams.getEncoded()), dsaParametersSet);
    }
}
