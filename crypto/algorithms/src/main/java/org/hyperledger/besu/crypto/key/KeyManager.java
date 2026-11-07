package org.hyperledger.besu.crypto.key;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.DigitalSignatureAlgorithm;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.KeyConfiguration;

public class KeyManager {
    private final KeyConfiguration keyConfig;
    private KeyPair nodeKeyPair;

    public KeyManager(final KeyConfiguration keyConfig) {
        this.keyConfig = keyConfig;
    }

    public void loadNodeKeyPairByPrivateKey(final DigitalSignatureAlgorithm activeDsa) {
        PrivateKey sk = loadPrivateKeyFromFile(activeDsa.getDsaParametersSet());
        PublicKey pk = KeyFactory.createPublicKey(sk, activeDsa.getDsaParametersSet());

        KeyPair keyPair = KeyFactory.createKeyPair(sk, pk);
        
        this.nodeKeyPair = keyPair;
    }

    public PrivateKey loadPrivateKeyFromFile(final DSAParametersSet parametersSet){
        final File skFile = keyConfig.getNodePrivateKeyFile();
        if (skFile == null) {
            throw new IllegalArgumentException(
                "No node private key file was given. " + notGeneratedHint(parametersSet));
        }
        try{
            String hexKey = readHexKey(skFile);
            return KeyFactory.createPrivateKey(Bytes.fromHexString(hexKey), parametersSet, keyConfig.getFirstKeyRepresentation(), keyConfig.getSecondKeyRepresentation());
        } catch(IOException ex) {
            // The cause is kept: a missing file and an unreadable one are different problems.
            throw new IllegalArgumentException(
                "Node private key file " + skFile + " could not be read ("
                    + ex.getClass().getSimpleName() + "). "
                    + notGeneratedHint(parametersSet),
                ex);
        }
    }

    /**
     * Unlike an elliptic-curve node key, a hybrid or post-quantum one is never generated on
     * start-up, which is the usual reason for the file to be missing.
     */
    private static String notGeneratedHint(final DSAParametersSet parametersSet) {
        return parametersSet.getName()
            + " node keys are not generated automatically: create one, for example with"
            + " 'besu operator generate-blockchain-config --node-dsa=" + parametersSet.getName()
            + "', and pass it with --node-private-key-file.";
    }

    private String readHexKey(final File file) throws IOException {
        final List<String> info = Files.readAllLines(file.toPath());
        if(info.size() != 1){
            throw new IllegalArgumentException(
                "Node private key file " + file + " does not contain a valid private key: expected a single line.");
        }
        return info.get(0);
    }

    public PrivateKey getNodePrivateKey() {
        return nodeKeyPair.getPrivateKey();
    }

    public PublicKey getNodePublicKey() {
        return nodeKeyPair.getPublicKey();
    }
}
