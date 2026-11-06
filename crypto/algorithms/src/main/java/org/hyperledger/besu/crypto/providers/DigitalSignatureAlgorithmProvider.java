package org.hyperledger.besu.crypto.providers;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SECPPrivateKey;
import org.hyperledger.besu.crypto.SECPPublicKey;
import org.hyperledger.besu.crypto.SignatureAlgorithm;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.DigitalSignatureAlgorithmConfiguration;
import org.hyperledger.besu.crypto.config.KeyConfiguration;
import org.hyperledger.besu.crypto.key.KeyManager;
import org.hyperledger.besu.crypto.key.types.CompositePrivateKey;
import org.hyperledger.besu.crypto.key.types.CompositePublicKey;
import org.hyperledger.besu.crypto.signature.Signature;

public class DigitalSignatureAlgorithmProvider implements NodeKeyProvider, KeyManagementProvider, VerifierProvider {
    private final DigitalSignatureAlgorithmConfiguration config;
    private final KeyManager keyManager;

    public DigitalSignatureAlgorithmProvider(
            final DigitalSignatureAlgorithmConfiguration digitalSignatureAlgorithmConfig,
            final KeyConfiguration keyConfiguration) {
        this.config = digitalSignatureAlgorithmConfig;
        this.keyManager = new KeyManager(keyConfiguration);
    }

    @Override
    public DigitalSignatureAlgorithm getAccountEnabledDSAById(final Short dsaId) {
        return config.getEnabledDSA(dsaId);
    }

    @Override
    public DSAParametersSet getActiveDsaParametersSet() {
        final DigitalSignatureAlgorithm activeDSA = config.getNodeActiveDSA();
        if (activeDSA != null) {
            return activeDSA.getDsaParametersSet();
        }
        return SignatureAlgorithmFactory.getInstance().getDsaParametersSet();
    }

    @Override
    public Signature sign(final Bytes32 data) {
        return config.getNodeActiveDSA().sign(data, keyManager.getNodePrivateKey());
    }

    @Override
    public Boolean verifySignature(final Bytes data, final Signature signature, final PublicKey pk) {
        return config.getNodeActiveDSA().verify(data, signature, pk);
    }

    @Override
    public KeyPair generateKeyPair(final DSAParametersSet dsaParams) {
        return config.getSupportedDSA(dsaParams.getName()).generateNodeKeyPair();
    }

    @Override
    public void loadNodeKeyPair() {
        keyManager.loadNodeKeyPairByPrivateKey(config.getNodeActiveDSA());
    }

    @Override
    public List<String> getAccountsSupportedDSANames() {
        return config.getAccountsSupportedDSANames();
    }

    @Override
    public boolean isNetworkCurveEnabled() {
        return config.isAccountEnabled(
            SignatureAlgorithmFactory.getInstance().getDsaParametersSet().getId());
    }

    @Override
    public DigitalSignatureAlgorithm getActiveDSA() {
        return config.getNodeActiveDSA();
    }

    @Override
    public PublicKey getPublicKey() {
        return keyManager.getNodePublicKey();
    }

    // TODO: we need to decide what to do with this method, maybe move to a component that handle key exchange
    @Override
    public Bytes32 calculateECDHKeyAgreement(final PublicKey partyKey) throws NodeKeyException {
        try {
            SignatureAlgorithm ecdsa = SignatureAlgorithmFactory.getInstance();
            SECPPublicKey secpPartyKey;
            if (partyKey instanceof CompositePublicKey composite) {
                if (composite.getFirstKey() instanceof SECPPublicKey secpPk) {
                    secpPartyKey = secpPk;
                } else if (composite.getSecondKey() instanceof SECPPublicKey secpPk) {
                    secpPartyKey = secpPk;
                } else {
                    throw new NodeKeyException("No SECP key found in CompositePublicKey");
                }
            } else if (partyKey instanceof SECPPublicKey secpPk) {
                secpPartyKey = secpPk;
            } else {
                throw new NodeKeyException("Besu only supports ECDH with SECP public key");
            }

            SECPPrivateKey secpPrivateKey;
            PrivateKey nodePrivateKey = keyManager.getNodePrivateKey();
            if (nodePrivateKey instanceof CompositePrivateKey composite) {
                if (composite.getFirstKey() instanceof SECPPrivateKey secp) {
                    secpPrivateKey = secp;
                } else if (composite.getSecondKey() instanceof SECPPrivateKey secp) {
                    secpPrivateKey = secp;
                } else {
                    throw new NodeKeyException("No SECP private key found in CompositePrivateKey");
                }
            } else if (nodePrivateKey instanceof SECPPrivateKey ){
                secpPrivateKey = (SECPPrivateKey) nodePrivateKey;
            } else {
                throw new NodeKeyException("Besu only supports ECDH with SECP private key");
            }

            return ecdsa.calculateECDHKeyAgreement(
                secpPrivateKey, secpPartyKey);
        } catch (final Exception e) {
        throw new NodeKeyException(
            "Unexpected error while calculating ECDH Key Agreement: " + e.getMessage(), e);
        }
    }
}
