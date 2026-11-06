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
package org.hyperledger.besu.crypto.config;

import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import java.util.Optional;

/**
 * A DSA type that is not enabled for accounts on this node was asked for, typically by a
 * transaction or code delegation being decoded.
 *
 * <p>It is deliberately not an {@link IllegalArgumentException}: callers that catch those for
 * malformed input would otherwise start treating it differently than before it existed, when the
 * lookup failed with a {@link NullPointerException}. Callers that answer a user catch it by name.
 */
public class DsaNotEnabledException extends RuntimeException {

  private final short dsaId;

  /**
   * A DSA type that is not among the enabled ones.
   *
   * @param dsaId the DSA type asked for
   */
  public DsaNotEnabledException(final short dsaId) {
    super(message(dsaId));
    this.dsaId = dsaId;
  }

  /**
   * The message for a DSA type that is not enabled, for callers that report it without throwing.
   *
   * @param dsaId the DSA type asked for
   * @return the message naming it
   */
  public static String message(final short dsaId) {
    return "DSA type " + describe(dsaId) + " is not enabled for accounts on this node";
  }

  /**
   * The DSA type that was asked for.
   *
   * @return its id
   */
  public short getDsaId() {
    return dsaId;
  }

  private static String describe(final short dsaId) {
    final String hex = String.format("0x%04x", dsaId & 0xffff);
    return name(dsaId).map(name -> name + " (" + hex + ")").orElse(hex);
  }

  private static Optional<String> name(final short dsaId) {
    try {
      return Optional.of(DSAParametersSet.fromId(dsaId).getName());
    } catch (final IllegalArgumentException unknownId) {
      return Optional.empty();
    }
  }
}
