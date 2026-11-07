/*
 * Copyright contributors to Hyperledger Besu.
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
package org.hyperledger.besu.cli;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.crypto.providers.DSAProviderFactory;

import java.io.IOException;
import java.nio.file.Path;

import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A hybrid or post-quantum --node-dsa needs --node-private-key-file: such keys are not generated
 * automatically, and the default key file is only for an elliptic-curve node key. Without the
 * option the node used to fail with a NullPointerException.
 */
class NodeDsaKeyFileTest extends CommandTestAbstract {

  private static final String KEY_FILE_ERROR = "needs --node-private-key-file";

  // A network of its own, so that the bootnodes of a built-in network play no part.
  private static final JsonObject GENESIS = new JsonObject().put("config", new JsonObject());

  @BeforeEach
  void resetDsa() {
    SignatureAlgorithmFactory.resetInstance();
    DSAProviderFactory.resetDsaProvider();
  }

  @AfterEach
  void resetDsaAgain() {
    resetDsa();
  }

  @Test
  void hybridNodeDsaWithoutKeyFileIsRefusedWithTheOptionNamed() throws IOException {
    parseCommand("--genesis-file", genesis().toString(), "--node-dsa", "SECP256K1-MLDSA44");

    assertThat(commandErrorOutput.toString(UTF_8))
        .contains("--node-dsa SECP256K1-MLDSA44 " + KEY_FILE_ERROR)
        .contains("not generated automatically")
        .doesNotContain("NullPointerException");
  }

  @Test
  void postQuantumNodeDsaWithoutKeyFileIsRefusedWithTheOptionNamed() throws IOException {
    parseCommand("--genesis-file", genesis().toString(), "--node-dsa", "MLDSA44");

    assertThat(commandErrorOutput.toString(UTF_8)).contains("--node-dsa MLDSA44 " + KEY_FILE_ERROR);
  }

  @Test
  void ellipticCurveNodeDsaKeepsTheDefaultKeyFile() throws IOException {
    parseCommand("--genesis-file", genesis().toString(), "--node-dsa", "SECP256K1");

    assertThat(commandErrorOutput.toString(UTF_8)).doesNotContain(KEY_FILE_ERROR);
    verify(mockControllerBuilder).nodeKey(any());
  }

  private Path genesis() throws IOException {
    return createFakeGenesisFile(GENESIS);
  }
}
