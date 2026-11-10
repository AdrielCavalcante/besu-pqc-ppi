package org.hyperledger.besu.crypto.providers;

import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DsaNotEnabledException;
import org.hyperledger.besu.crypto.signature.Signature;

/**
 * What a node verifies with before any DSA configuration is set, as in unit tests, the evmtool and
 * the reference tests, which never call {@link DSAProviderFactory#setDsaProvider}. It behaves as
 * upstream Besu: the network's curve signs standard transactions, and no DSA type is enabled for
 * flexible ones, not even the curve's.
 */
final class UnconfiguredVerifierProvider implements VerifierProvider {

    @Override
    public DigitalSignatureAlgorithm getAccountEnabledDSAById(final Short dsaId) {
        throw new DsaNotEnabledException(dsaId);
    }

    @Override
    public DSAParametersSet getActiveDsaParametersSet() {
        return getActiveDSA().getDsaParametersSet();
    }

    @Override
    public Boolean verifySignature(final Bytes data, final Signature signature, final PublicKey pk) {
        return getActiveDSA().verify(data, signature, pk);
    }

    @Override
    public List<String> getAccountsSupportedDSANames() {
        return List.of();
    }

    @Override
    public boolean isNetworkCurveEnabled() {
        return true;
    }

    @Override
    public DigitalSignatureAlgorithm getActiveDSA() {
        return SignatureAlgorithmFactory.getInstance();
    }
}
