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
package org.hyperledger.besu.crypto;

import org.hyperledger.besu.crypto.algorithms.Falcon;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;
import org.hyperledger.besu.crypto.config.SupportedAlgorithms;
import org.hyperledger.besu.crypto.signature.types.FalconSignature;

import java.util.Collection;
import java.util.EnumMap;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.OptionalLong;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.results.Result;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.CommandLineOptionException;
import org.openjdk.jmh.runner.options.CommandLineOptions;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

/**
 * Runs {@link SignatureCostBenchmark} for every algorithm in one JMH run and prices each one from
 * the secp256k1 key recovery in two ways:
 *
 * <pre>
 * gas (relative) = ECRECOVER_GAS * time(algorithm) / time(secp256k1)
 * gas (absolute) = gas(secp256k1) * time(algorithm) / time(secp256k1),
 *                  where gas(secp256k1) = time(secp256k1) * GAS_PER_SECOND
 * </pre>
 *
 * <p>The relative column anchors secp256k1 at the 3000 gas Ethereum already charges for it, so it
 * does not depend on how fast the machine is. It does depend on which implementations run: the
 * post-quantum algorithms are pure Java, while secp256k1 runs on the native libsecp256k1 when it
 * loads and on BouncyCastle otherwise, which is many times slower. A Java baseline would make every
 * other algorithm look cheap, so the report refuses to run without the native secp256k1 that
 * production nodes use, unless {@value #ALLOW_JAVA_BASELINE} is set.
 *
 * <p>The absolute column anchors secp256k1 at its measured time, converted with the 100 Mgas/s
 * target that Besu's evmtool uses to derive gas from execution time; it equals time(algorithm) *
 * GAS_PER_SECOND and so depends on the machine.
 *
 * <p>All algorithms are measured in the same run, so load on the machine affects the baseline and
 * the algorithm alike and mostly cancels out in the ratio. The conservative column takes the upper
 * end of the algorithm's error interval over the lower end of the baseline's, as a bound to round
 * the relative gas up to.
 */
public class SignatureGasReport {

  /** Gas of the ECRECOVER precompile, taken as the price of one secp256k1 key recovery. */
  static final long ECRECOVER_GAS = 3_000L;

  /** The 100 Mgas/s target of Besu's evmtool benchmarks (BenchmarkExecutor): 1 gas = 10 ns. */
  static final long GAS_PER_SECOND = 100_000_000L;

  /** System property that lets the report run with the Java (BouncyCastle) secp256k1 baseline. */
  static final String ALLOW_JAVA_BASELINE = "signatureGasReport.allowJavaBaseline";

  /** Base gas of every transaction, which already pays for one ECDSA signature. */
  static final long TRANSACTION_BASE_GAS = 21_000L;

  /** Gas of a non-zero calldata byte (EIP-2028), charged for every signature and key byte. */
  static final long GAS_PER_BYTE = 16L;

  /** Bytes of the r, s and v of an ECDSA signature, which the base gas already pays for. */
  static final long ECDSA_SIGNATURE_BYTES = 65L;

  /** What is left of the base gas once the ECDSA signature it pays for is taken out. */
  static final long FLEXIBLE_BASE_GAS =
      TRANSACTION_BASE_GAS - ECRECOVER_GAS - ECDSA_SIGNATURE_BYTES * GAS_PER_BYTE;

  private static final double MICROSECONDS_PER_SECOND = 1_000_000D;

  /**
   * Runs the benchmark and prints the gas table.
   *
   * @param args JMH command-line options, e.g. {@code -p dsaType=SECP256K1,MLDSA87} to measure only
   *     some algorithms; the secp256k1 baseline must be among them
   * @throws RunnerException if JMH fails to run
   * @throws CommandLineOptionException if the options cannot be parsed
   */
  public static void main(final String[] args)
      throws RunnerException, CommandLineOptionException {
    // The forks run from the same jar on the same machine, so they load the same implementations
    // as this JVM does.
    final boolean nativeSecp256k1 = isNative(SECP256K1::new);
    final boolean nativeSecp256r1 = isNative(SECP256R1::new);
    if (!nativeSecp256k1 && !Boolean.getBoolean(ALLOW_JAVA_BASELINE)) {
      throw new IllegalStateException(
          "The native secp256k1 library did not load, so the baseline would be the Java"
              + " implementation and every relative gas value would be far too low. Run on a"
              + " platform where it loads, or set -D"
              + ALLOW_JAVA_BASELINE
              + "=true to run anyway.");
    }

    final Options options =
        new OptionsBuilder()
            .parent(new CommandLineOptions(args))
            .include(SignatureCostBenchmark.class.getName())
            // The gas math needs the average time per signature, in microseconds for the absolute
            // column, whatever mode or unit the command line asks for.
            .mode(Mode.AverageTime)
            .timeUnit(TimeUnit.MICROSECONDS)
            .build();
    final Collection<RunResult> results = new Runner(options).run();

    final Map<DSAParametersSet, Result<?>> byType = new EnumMap<>(DSAParametersSet.class);
    for (final RunResult result : results) {
      byType.put(
          DSAParametersSet.valueOf(result.getParams().getParam("dsaType")),
          result.getPrimaryResult());
    }

    final Result<?> baseline = byType.get(DSAParametersSet.SECP256K1);
    if (baseline == null) {
      throw new IllegalStateException("The secp256k1 baseline was not measured");
    }

    final double baselineAbsoluteGas =
        baseline.getScore() / MICROSECONDS_PER_SECOND * GAS_PER_SECOND;

    System.out.println();
    System.out.printf("SECP256K1 implementation: %s%n", implementation(nativeSecp256k1));
    System.out.printf("SECP256R1 implementation: %s%n", implementation(nativeSecp256r1));
    if (!nativeSecp256k1) {
      System.out.println(
          "WARNING: the secp256k1 baseline is the Java implementation, so every relative gas"
              + " value is far too low. Do not use these numbers for pricing.");
    }
    System.out.println();
    System.out.printf(
        "gas (relative) = %,d gas x time / time(SECP256K1), anchored at ECRECOVER%n",
        ECRECOVER_GAS);
    System.out.printf(
        "gas (absolute) = %,.0f gas x time / time(SECP256K1), where %,.0f gas = %.3f %s x %,d gas/s"
            + " (100 Mgas/s, 1 gas = 10 ns)%n",
        baselineAbsoluteGas,
        baselineAbsoluteGas,
        baseline.getScore(),
        baseline.getScoreUnit(),
        GAS_PER_SECOND);
    System.out.println();
    System.out.printf(
        "%-22s %12s %10s %7s %15s %15s %15s %12s%n",
        "dsaType",
        "time (" + baseline.getScoreUnit() + ")",
        "+/- error",
        "ratio",
        "gas (relative)",
        "conserv. (rel.)",
        "gas (absolute)",
        "total gas");
    final Map<DSAParametersSet, Long> relativeGas = new EnumMap<>(DSAParametersSet.class);
    for (final Map.Entry<DSAParametersSet, Result<?>> entry : byType.entrySet()) {
      final Result<?> result = entry.getValue();
      final double ratio = result.getScore() / baseline.getScore();
      final OptionalDouble error = error(result);
      final OptionalLong conservative = conservativeGas(result, baseline);
      final long relative = (long) Math.ceil(ECRECOVER_GAS * ratio);
      relativeGas.put(entry.getKey(), relative);
      System.out.printf(
          "%-22s %12.3f %10s %7.2f %,15d %15s %,15d %,12d%n",
          entry.getKey().getName(),
          result.getScore(),
          error.isPresent() ? String.format("%.3f", error.getAsDouble()) : "n/a",
          ratio,
          relative,
          conservative.isPresent() ? String.format("%,d", conservative.getAsLong()) : "n/a",
          (long) Math.ceil(baselineAbsoluteGas * ratio),
          ByteFootprint.of(entry.getKey()).totalGas(relative));
    }

    // JMH drops every result of a parameter whose fork failed, so say which ones are missing
    // rather than leave them out of the table without a word.
    for (final DSAParametersSet dsaType : DSAParametersSet.values()) {
      if (!byType.containsKey(dsaType)) {
        System.out.printf("%-22s %14s%n", dsaType.getName(), "no result");
      }
    }

    final boolean anyMissingInterval =
        byType.values().stream().anyMatch(result -> error(result).isEmpty());
    final OptionalDouble baselineError = error(baseline);
    if (anyMissingInterval) {
      System.out.println();
      System.out.println(
          "n/a: JMH could not compute an error interval, which takes at least two samples per"
              + " algorithm. Run more iterations.");
    }
    if (baselineError.isPresent() && baselineError.getAsDouble() >= baseline.getScore()) {
      System.out.println();
      System.out.println(
          "n/a: the baseline's error is as large as its score, so no lower bound exists for it."
              + " Run more iterations or on an idle machine.");
    }

    printTotalGasExplanation(relativeGas);
  }

  /**
   * Explains the total gas column: the formula, where each of its values comes from, and the
   * breakdown for every algorithm measured.
   */
  private static void printTotalGasExplanation(final Map<DSAParametersSet, Long> relativeGas) {
    final String[] lines = {
      "",
      "How the total gas is computed",
      "",
      "The total gas is what a flexible transaction would pay for its signature, in place of the",
      "21,000 base gas of a legacy transaction. It is a fixed worst case per dsaType, so it can be",
      "known before the transaction is signed.",
      "",
      String.format(
          "  total gas = %,d - %,d - %d x %d + gas (relative) + %d x (signature bytes + key bytes)",
          TRANSACTION_BASE_GAS,
          ECRECOVER_GAS,
          ECDSA_SIGNATURE_BYTES,
          GAS_PER_BYTE,
          GAS_PER_BYTE),
      String.format(
          "            = %,d + gas (relative) + %d x (signature bytes + key bytes)",
          FLEXIBLE_BASE_GAS, GAS_PER_BYTE),
      "",
      String.format(
          "  %,d           base gas of every transaction. It already pays for one ECDSA signature:",
          TRANSACTION_BASE_GAS),
      "                   recovering the signer from it, and carrying its bytes.",
      String.format(
          "  - %,d          the recovery of that signature, priced as the ECRECOVER precompile,",
          ECRECOVER_GAS),
      "                   which runs the same recovery. The algorithm's own CPU cost replaces it.",
      String.format(
          "  - %d x %d        the %d bytes of r, s and v of that signature (%,d gas). The bytes",
          ECDSA_SIGNATURE_BYTES,
          GAS_PER_BYTE,
          ECDSA_SIGNATURE_BYTES,
          ECDSA_SIGNATURE_BYTES * GAS_PER_BYTE),
      "                   the flexible transaction carries replace them.",
      "  gas (relative)   CPU cost of authenticating the signature, from the table above: a key",
      "                   recovery for recoverable algorithms, a verification for the others, and",
      "                   each half by its own rule for hybrids.",
      String.format(
          "  %d               gas per byte, the price of a non-zero calldata byte (EIP-2028). Zero",
          GAS_PER_BYTE),
      "                   bytes cost 4, but signatures and keys are close to random and their",
      "                   bytes are not known before signing, so every byte is priced as",
      "                   non-zero.",
      "  signature bytes  the algorithm's signature length. Falcon signatures vary in length, so",
      "                   their maximum is used; a hybrid adds the lengths of its two halves.",
      "  key bytes        the public key the transaction carries. A key that can be recovered from",
      "                   the signature is not carried (0). A hybrid carries only the key of its",
      "                   half that cannot be recovered.",
      "",
      "  Not included: calldata, access list, code delegations and contract creation, which are",
      "  charged as for any other transaction.",
      ""
    };
    for (final String line : lines) {
      System.out.println(line);
    }

    System.out.printf(
        "%-22s %10s %10s %11s %10s %12s%n",
        "dsaType", "sig bytes", "key bytes", "bytes gas", "CPU gas", "total gas");
    for (final Map.Entry<DSAParametersSet, Long> entry : relativeGas.entrySet()) {
      final ByteFootprint footprint = ByteFootprint.of(entry.getKey());
      System.out.printf(
          "%-22s %,10d %,10d %,11d %,10d %,12d%n",
          entry.getKey().getName(),
          footprint.signatureBytes(),
          footprint.keyBytes(),
          footprint.bytesGas(),
          entry.getValue(),
          footprint.totalGas(entry.getValue()));
    }
    System.out.printf(
        "%ntotal gas = %,d + CPU gas + bytes gas, where bytes gas = %d x (sig bytes + key bytes)%n",
        FLEXIBLE_BASE_GAS,
        GAS_PER_BYTE);
  }

  /**
   * The bytes a flexible transaction carries for its signature: the signature at its maximum
   * length, and the public key unless it can be recovered from the signature.
   */
  private record ByteFootprint(long signatureBytes, long keyBytes) {

    static ByteFootprint of(final DSAParametersSet dsaType) {
      final DigitalSignatureAlgorithm dsa =
          new SupportedAlgorithms().getDSAByName(dsaType.getName()).get();
      return new ByteFootprint(signatureBytes(dsa), carriedKeyBytes(dsa));
    }

    long bytesGas() {
      return GAS_PER_BYTE * (signatureBytes + keyBytes);
    }

    long totalGas(final long cpuGas) {
      return FLEXIBLE_BASE_GAS + cpuGas + bytesGas();
    }

    private static long signatureBytes(final DigitalSignatureAlgorithm dsa) {
      if (dsa instanceof HybridDigitalSignatureAlgorithm hybrid) {
        return signatureBytes(hybrid.getFirstAlgorithm())
            + signatureBytes(hybrid.getSecondAlgorithm());
      }
      final DSAParametersSet parameters = dsa.getDsaParametersSet();
      if (parameters.getSignatureLength() != null) {
        return parameters.getSignatureLength();
      }
      if (Falcon.supportedParameterSets().contains(parameters)) {
        return FalconSignature.maxLength(parameters);
      }
      throw new IllegalStateException(
          "No maximum signature length is known for " + parameters.getName());
    }

    private static long carriedKeyBytes(final DigitalSignatureAlgorithm dsa) {
      if (dsa instanceof HybridDigitalSignatureAlgorithm hybrid) {
        return carriedKeyBytes(hybrid.getFirstAlgorithm())
            + carriedKeyBytes(hybrid.getSecondAlgorithm());
      }
      if (dsa instanceof PublicKeyRecoverable) {
        return 0;
      }
      return dsa.getDsaParametersSet().getPublicKeyLength();
    }
  }

  /**
   * The relative gas at the pessimistic ends of both error intervals, or empty when either
   * interval is unknown or the baseline's reaches zero, since the bound then does not exist.
   */
  private static OptionalLong conservativeGas(final Result<?> result, final Result<?> baseline) {
    final OptionalDouble error = error(result);
    final OptionalDouble baselineError = error(baseline);
    if (error.isEmpty() || baselineError.isEmpty()) {
      return OptionalLong.empty();
    }
    final double baselineLowerBound = baseline.getScore() - baselineError.getAsDouble();
    if (baselineLowerBound <= 0) {
      return OptionalLong.empty();
    }
    final double ratio = (result.getScore() + error.getAsDouble()) / baselineLowerBound;
    return OptionalLong.of((long) Math.ceil(ECRECOVER_GAS * ratio));
  }

  /**
   * Whether the algorithm runs on its native library. One whose class cannot even load, as when JNA
   * itself is missing, counts as not native.
   */
  private static boolean isNative(final Supplier<SignatureAlgorithm> algorithm) {
    try {
      return algorithm.get().isNative();
    } catch (final LinkageError e) {
      return false;
    }
  }

  private static String implementation(final boolean isNative) {
    return isNative ? "native" : "Java (BouncyCastle)";
  }

  /**
   * The half-width of the 99.9% confidence interval, or empty when JMH could not compute it, as
   * with a single sample. An unknown interval is not a zero one, so it is never reported as such.
   */
  private static OptionalDouble error(final Result<?> result) {
    final double error = result.getScoreError();
    return Double.isNaN(error) ? OptionalDouble.empty() : OptionalDouble.of(error);
  }
}
