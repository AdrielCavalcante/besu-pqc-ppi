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
package org.hyperledger.besu.crypto;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.KeyConfiguration;
import org.hyperledger.besu.crypto.key.KeyManager;
import org.hyperledger.besu.crypto.key.PrivateKeyRepresentation;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * How a hybrid node key file that is missing, not given, or of the wrong kind is reported. Each case
 * used to surface as an unrelated error: a NullPointerException, "index is out of bounds" or a
 * message without the cause.
 */
class KeyManagerTest {

  private static final DSAParametersSet HYBRID = DSAParametersSet.SECP256K1MLDSA44;

  @Test
  void aMissingKeyFileIsReportedWithItsPathAndCause(@TempDir final Path dir) {
    final File missing = dir.resolve("key").toFile();
    final KeyManager keyManager = new KeyManager(hybridConfig(missing));

    assertThatThrownBy(() -> keyManager.loadPrivateKeyFromFile(HYBRID))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(missing.toString())
        .hasMessageContaining("not generated automatically")
        .hasMessageContaining("--node-private-key-file")
        .hasCauseInstanceOf(NoSuchFileException.class);
  }

  @Test
  void noKeyFileAtAllIsReportedInsteadOfANullPointerException() {
    final KeyManager keyManager = new KeyManager(hybridConfig(null));

    assertThatThrownBy(() -> keyManager.loadPrivateKeyFromFile(HYBRID))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("No node private key file was given")
        .hasMessageContaining("--node-private-key-file");
  }

  @Test
  void aClassicalKeyFileIsRefusedForAHybridNodeDsa(@TempDir final Path dir) throws IOException {
    final Path classicalKey = dir.resolve("key");
    Files.writeString(classicalKey, "0x" + "11".repeat(32), UTF_8);
    final KeyManager keyManager = new KeyManager(hybridConfig(classicalKey.toFile()));

    assertThatThrownBy(() -> keyManager.loadPrivateKeyFromFile(HYBRID))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("SECP256K1-MLDSA44 private key must be 2592 bytes, got 32");
  }

  @Test
  void aKeyFileWithMoreThanOneLineIsRefused(@TempDir final Path dir) throws IOException {
    final Path twoLines = dir.resolve("key");
    Files.writeString(twoLines, "0x11\n0x22\n", UTF_8);
    final KeyManager keyManager = new KeyManager(hybridConfig(twoLines.toFile()));

    assertThatThrownBy(() -> keyManager.loadPrivateKeyFromFile(HYBRID))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining(twoLines.toString())
        .hasMessageContaining("expected a single line");
  }

  private static KeyConfiguration hybridConfig(final File keyFile) {
    return KeyConfiguration.createHybridKeyConfig(
        keyFile, PrivateKeyRepresentation.EXPANDED, PrivateKeyRepresentation.EXPANDED);
  }
}
