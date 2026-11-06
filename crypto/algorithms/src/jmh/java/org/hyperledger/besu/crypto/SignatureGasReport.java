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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.OptionalDouble;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.infra.BenchmarkParams;
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
 *
 * <p>The table is printed to the console, and the full report, with how the total gas is computed,
 * is written as an HTML page to the directory given with {@value #REPORT_DIR_OPTION}, or to {@value
 * #DEFAULT_REPORT_DIR} under the working directory.
 */
public class SignatureGasReport {

  /** Gas of the ECRECOVER precompile, taken as the price of one secp256k1 key recovery. */
  static final long ECRECOVER_GAS = 3_000L;

  /** The 100 Mgas/s target of Besu's evmtool benchmarks (BenchmarkExecutor): 1 gas = 10 ns. */
  static final long GAS_PER_SECOND = 100_000_000L;

  /** System property that lets the report run with the Java (BouncyCastle) secp256k1 baseline. */
  static final String ALLOW_JAVA_BASELINE = "signatureGasReport.allowJavaBaseline";

  /** Option that sets the directory of the HTML report, as {@code --report-dir=<dir>}. */
  static final String REPORT_DIR_OPTION = "--report-dir";

  /** Where the HTML report goes by default: next to the other reports of a Gradle build. */
  static final String DEFAULT_REPORT_DIR = "build/reports/signature-gas";

  /** Base gas of every transaction, which already pays for one ECDSA signature. */
  static final long TRANSACTION_BASE_GAS = 21_000L;

  /** Gas of a non-zero calldata byte (EIP-2028), charged for every signature and key byte. */
  static final long GAS_PER_BYTE = 16L;

  /** Gas of a zero calldata byte, which signature and key bytes are never priced at. */
  static final long GAS_PER_ZERO_BYTE = 4L;

  /** Bytes of the r, s and v of an ECDSA signature, which the base gas already pays for. */
  static final long ECDSA_SIGNATURE_BYTES = 65L;

  /** What is left of the base gas once the ECDSA signature it pays for is taken out. */
  static final long FLEXIBLE_BASE_GAS =
      TRANSACTION_BASE_GAS - ECRECOVER_GAS - ECDSA_SIGNATURE_BYTES * GAS_PER_BYTE;

  /** Error, as a share of the score, above which a measurement is flagged as noisy. */
  static final double HIGH_RELATIVE_ERROR = 0.05;

  private static final double MICROSECONDS_PER_SECOND = 1_000_000D;

  /**
   * Runs the benchmark, prints the gas table and writes the HTML report.
   *
   * @param args {@code --report-dir=<dir>} for where to write the HTML report, followed by JMH
   *     command-line options, e.g. {@code -p dsaType=SECP256K1,MLDSA87} to measure only some
   *     algorithms; the secp256k1 baseline must be among them
   * @throws RunnerException if JMH fails to run
   * @throws CommandLineOptionException if the options cannot be parsed
   * @throws IOException if the HTML report cannot be written
   */
  public static void main(final String[] args)
      throws RunnerException, CommandLineOptionException, IOException {
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

    final List<String> jmhArgs = new ArrayList<>(List.of(args));
    final Path reportDir = reportDir(jmhArgs);
    // Fail now rather than after the benchmark has run for minutes.
    Files.createDirectories(reportDir);
    if (!Files.isWritable(reportDir)) {
      throw new IOException("Cannot write the HTML report to " + reportDir.toAbsolutePath());
    }

    final Options options =
        new OptionsBuilder()
            .parent(new CommandLineOptions(jmhArgs.toArray(String[]::new)))
            .include(SignatureCostBenchmark.class.getName())
            // The gas math needs the average time per signature, in microseconds for the absolute
            // column, whatever mode or unit the command line asks for.
            .mode(Mode.AverageTime)
            .timeUnit(TimeUnit.MICROSECONDS)
            .build();
    final Collection<RunResult> results = new Runner(options).run();

    final Report report = Report.of(results, nativeSecp256k1, nativeSecp256r1);
    print(report);
    final Path html = SignatureGasHtmlReport.write(report, reportDir);
    System.out.println();
    System.out.println("HTML report: " + html.toAbsolutePath().normalize());
  }

  /**
   * Takes the {@value #REPORT_DIR_OPTION} option out of the arguments, so the rest can go to JMH,
   * which rejects options it does not know. It is given as {@code --report-dir=<dir>} or {@code
   * --report-dir <dir>}; a leading {@code ~} stands for the home directory.
   */
  static Path reportDir(final List<String> args) {
    String dir = DEFAULT_REPORT_DIR;
    for (int i = 0; i < args.size(); ) {
      final String arg = args.get(i);
      if (arg.startsWith(REPORT_DIR_OPTION + "=")) {
        dir = arg.substring(REPORT_DIR_OPTION.length() + 1);
        args.remove(i);
      } else if (arg.equals(REPORT_DIR_OPTION)) {
        if (i + 1 >= args.size()) {
          throw new IllegalArgumentException(REPORT_DIR_OPTION + " needs a directory");
        }
        dir = args.get(i + 1);
        args.subList(i, i + 2).clear();
      } else {
        i++;
      }
    }
    if (dir.isBlank()) {
      throw new IllegalArgumentException(REPORT_DIR_OPTION + " needs a directory");
    }
    if (dir.equals("~") || dir.startsWith("~/")) {
      dir = System.getProperty("user.home") + dir.substring(1);
    }
    return Path.of(dir);
  }

  /** Everything the report shows, computed once for the console and the HTML page. */
  record Report(
      ZonedDateTime createdAt,
      BenchmarkParams params,
      boolean nativeSecp256k1,
      boolean nativeSecp256r1,
      Result<?> baseline,
      double baselineAbsoluteGas,
      List<Row> rows,
      List<DSAParametersSet> missing,
      List<String> notes) {

    static Report of(
        final Collection<RunResult> results,
        final boolean nativeSecp256k1,
        final boolean nativeSecp256r1) {
      final Map<DSAParametersSet, Result<?>> byType = new EnumMap<>(DSAParametersSet.class);
      BenchmarkParams params = null;
      for (final RunResult result : results) {
        params = result.getParams();
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

      final List<Row> rows = new ArrayList<>();
      for (final Map.Entry<DSAParametersSet, Result<?>> entry : byType.entrySet()) {
        final Result<?> result = entry.getValue();
        final double ratio = result.getScore() / baseline.getScore();
        rows.add(
            new Row(
                entry.getKey(),
                result,
                ratio,
                (long) Math.ceil(ECRECOVER_GAS * ratio),
                conservativeGas(result, baseline),
                (long) Math.ceil(baselineAbsoluteGas * ratio),
                ByteFootprint.of(entry.getKey())));
      }

      // JMH drops every result of a parameter whose fork failed, so say which ones are missing
      // rather than leave them out of the report without a word.
      final List<DSAParametersSet> missing = new ArrayList<>();
      for (final DSAParametersSet dsaType : DSAParametersSet.values()) {
        if (!byType.containsKey(dsaType)) {
          missing.add(dsaType);
        }
      }

      return new Report(
          ZonedDateTime.now(ZoneId.systemDefault()),
          params,
          nativeSecp256k1,
          nativeSecp256r1,
          baseline,
          baselineAbsoluteGas,
          List.copyOf(rows),
          List.copyOf(missing),
          notes(rows, baseline));
    }

    private static List<String> notes(final List<Row> rows, final Result<?> baseline) {
      final List<String> notes = new ArrayList<>();
      if (rows.stream().anyMatch(row -> row.error().isEmpty())) {
        notes.add(
            "n/a: JMH could not compute an error interval, which takes at least two samples per"
                + " algorithm. Run more iterations.");
      }
      final OptionalDouble baselineError = error(baseline);
      if (baselineError.isPresent() && baselineError.getAsDouble() >= baseline.getScore()) {
        notes.add(
            "n/a: the baseline's error is as large as its score, so no lower bound exists for it."
                + " Run more iterations or on an idle machine.");
      }
      final List<Row> noisy = rows.stream().filter(Row::isNoisy).toList();
      if (!noisy.isEmpty()) {
        // The baseline divides every other score, so it is always re-run with them.
        final Set<DSAParametersSet> rerun = EnumSet.of(DSAParametersSet.SECP256K1);
        noisy.forEach(row -> rerun.add(row.dsaType()));
        notes.add(
            String.format(
                Locale.ROOT,
                "High error, above %.0f%% of the score: %s. Too few iterations or load on the"
                    + " machine; re-run them on an idle machine with -p dsaType=%s",
                100 * HIGH_RELATIVE_ERROR,
                noisy.stream()
                    .map(
                        row ->
                            String.format(
                                Locale.ROOT,
                                "%s (%.1f%%)",
                                row.dsaType().getName(),
                                100 * row.relativeError().orElseThrow()))
                    .collect(Collectors.joining(", ")),
                rerun.stream().map(Enum::name).collect(Collectors.joining(","))));
      }
      return List.copyOf(notes);
    }

    String unit() {
      return baseline.getScoreUnit();
    }
  }

  /** The measurement of one algorithm and the gas derived from it. */
  record Row(
      DSAParametersSet dsaType,
      Result<?> result,
      double ratio,
      long relativeGas,
      OptionalLong conservativeGas,
      long absoluteGas,
      ByteFootprint footprint) {

    OptionalDouble error() {
      return SignatureGasReport.error(result);
    }

    OptionalDouble relativeError() {
      final OptionalDouble error = error();
      return error.isPresent()
          ? OptionalDouble.of(error.getAsDouble() / result.getScore())
          : OptionalDouble.empty();
    }

    boolean isNoisy() {
      final OptionalDouble relativeError = relativeError();
      return relativeError.isPresent() && relativeError.getAsDouble() > HIGH_RELATIVE_ERROR;
    }

    long totalGas() {
      return footprint.totalGas(relativeGas);
    }
  }

  private static void print(final Report report) {
    System.out.println();
    System.out.printf("SECP256K1 implementation: %s%n", implementation(report.nativeSecp256k1()));
    System.out.printf("SECP256R1 implementation: %s%n", implementation(report.nativeSecp256r1()));
    if (!report.nativeSecp256k1()) {
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
        report.baselineAbsoluteGas(),
        report.baselineAbsoluteGas(),
        report.baseline().getScore(),
        report.unit(),
        GAS_PER_SECOND);
    System.out.printf(
        "total gas      = %,d + gas (relative) + %d x (signature bytes + key bytes)%n",
        FLEXIBLE_BASE_GAS, GAS_PER_BYTE);
    System.out.println();
    System.out.printf(
        "%-22s %12s %10s %7s %15s %15s %15s %12s%n",
        "dsaType",
        "time (" + report.unit() + ")",
        "+/- error",
        "ratio",
        "gas (relative)",
        "conserv. (rel.)",
        "gas (absolute)",
        "total gas");
    for (final Row row : report.rows()) {
      final OptionalDouble error = row.error();
      final OptionalLong conservative = row.conservativeGas();
      System.out.printf(
          "%-22s %12.3f %10s %7.2f %,15d %15s %,15d %,12d%n",
          row.dsaType().getName(),
          row.result().getScore(),
          error.isPresent() ? String.format("%.3f", error.getAsDouble()) : "n/a",
          row.ratio(),
          row.relativeGas(),
          conservative.isPresent() ? String.format("%,d", conservative.getAsLong()) : "n/a",
          row.absoluteGas(),
          row.totalGas());
    }
    for (final DSAParametersSet dsaType : report.missing()) {
      System.out.printf("%-22s %14s%n", dsaType.getName(), "no result");
    }
    for (final String note : report.notes()) {
      System.out.println();
      System.out.println(note);
    }
  }

  /**
   * The bytes a flexible transaction carries for its signature: the signature at its maximum
   * length, and the public key unless it can be recovered from the signature.
   */
  record ByteFootprint(long signatureBytes, long keyBytes) {

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
   * The relative gas at the pessimistic ends of both error intervals, or empty when either interval
   * is unknown or the baseline's reaches zero, since the bound then does not exist.
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

  static String implementation(final boolean isNative) {
    return isNative ? "native" : "Java (BouncyCastle)";
  }

  /**
   * The half-width of the 99.9% confidence interval, or empty when JMH could not compute it, as
   * with a single sample. An unknown interval is not a zero one, so it is never reported as such.
   */
  static OptionalDouble error(final Result<?> result) {
    final double error = result.getScoreError();
    return Double.isNaN(error) ? OptionalDouble.empty() : OptionalDouble.of(error);
  }
}
