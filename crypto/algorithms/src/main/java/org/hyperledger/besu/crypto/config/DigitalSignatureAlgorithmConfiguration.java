package org.hyperledger.besu.crypto.config;

import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import java.util.stream.Collectors;

import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;

public class DigitalSignatureAlgorithmConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(DigitalSignatureAlgorithmConfiguration.class);
    private static final SupportedAlgorithms supportedAlgorithms = new SupportedAlgorithms();
    private DigitalSignatureAlgorithm nodeActiveDSA;
    // One instance per enabled algorithm, built with the configuration. Every transaction decode
    // and signature check looks its algorithm up here, and constructing one is expensive: each
    // secp256k1 half creates and registers a BouncyCastleProvider, each ML-DSA half a
    // BouncyCastlePQCProvider. The algorithms keep no per-operation state, so one instance serves
    // every thread.
    private ImmutableMap<Short, DigitalSignatureAlgorithm> accountsEnabledDSAs;

    public DigitalSignatureAlgorithmConfiguration() {
        this.nodeActiveDSA = null;
    }

    public void setNodeActiveDSA(final String algorithmName)
            throws InvalidAlgorithmParameterException {

        if (!supportedAlgorithms.supports(algorithmName)) {
            throw new InvalidAlgorithmParameterException(
                "Algorithm name provided is not supported");
        }

        this.nodeActiveDSA = supportedAlgorithms.getDSAByName(algorithmName).get();
    }

    public DigitalSignatureAlgorithm getNodeActiveDSA() {
        return nodeActiveDSA;
    }

    public void buildAccountSupportedAlgorithms(
            final List<DSAParametersSet> selectedAccountDSAs)
            throws InvalidAlgorithmParameterException {

        final ImmutableMap.Builder<Short, DigitalSignatureAlgorithm>
            builder = ImmutableMap.builder();

        for (final DSAParametersSet param : selectedAccountDSAs) {
            if (supportedAlgorithms.supports(param.getName())) {
                builder.put(
                    param.getId(),
                    supportedAlgorithms.getDSAByName(param.getName()).get());
                continue;
            }

            throw new InvalidAlgorithmParameterException(
                "Algorithm name provided is not supported");
        }

        this.accountsEnabledDSAs = builder.build();

        LOG.info(
            "Account-enabled DSAs: {}",
            accountsEnabledDSAs.keySet().stream()
                .map(DSAParametersSet::fromId)
                .map(DSAParametersSet::getName)
                .collect(Collectors.joining(", "))
        );
    }

    public DigitalSignatureAlgorithm getEnabledDSA(
            final Short dsaId) {
        final DigitalSignatureAlgorithm enabledDSA = accountsEnabledDSAs.get(dsaId);
        // An id that is not enabled fails the lookup rather than yielding null to callers that
        // never expected it, naming the type asked for so the error can reach the user.
        if (enabledDSA == null) {
            throw new DsaNotEnabledException(dsaId);
        }
        return enabledDSA;
    }

    public boolean isAccountEnabled(final Short dsaId) {
        return accountsEnabledDSAs.containsKey(dsaId);
    }

    public DigitalSignatureAlgorithm getSupportedDSA(final String dsaName){
        return supportedAlgorithms.getDSAByName(dsaName).get();
    }

    public List<String> getAccountsSupportedDSANames() {
        return accountsEnabledDSAs.keySet().stream()
            .map(DSAParametersSet::fromId)
            .map(DSAParametersSet::getName)
            .collect(Collectors.toList());
    }
}