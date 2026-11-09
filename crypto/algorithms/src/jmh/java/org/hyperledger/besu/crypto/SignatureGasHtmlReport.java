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

import static org.hyperledger.besu.crypto.SignatureGasReport.ECDSA_SIGNATURE_BYTES;
import static org.hyperledger.besu.crypto.SignatureGasReport.ECRECOVER_GAS;
import static org.hyperledger.besu.crypto.SignatureGasReport.FLEXIBLE_BASE_GAS;
import static org.hyperledger.besu.crypto.SignatureGasReport.GAS_PER_BYTE;
import static org.hyperledger.besu.crypto.SignatureGasReport.GAS_PER_SECOND;
import static org.hyperledger.besu.crypto.SignatureGasReport.GAS_PER_ZERO_BYTE;
import static org.hyperledger.besu.crypto.SignatureGasReport.TRANSACTION_BASE_GAS;

import org.hyperledger.besu.crypto.SignatureGasReport.Report;
import org.hyperledger.besu.crypto.SignatureGasReport.Row;
import org.hyperledger.besu.crypto.algorithms.parameters.DSAParametersSet;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Optional;
import java.util.OptionalDouble;
import java.util.OptionalLong;
import java.util.stream.Stream;

import org.openjdk.jmh.infra.BenchmarkParams;

/**
 * Writes a {@link SignatureGasReport} as a single self-contained HTML page: no scripts and nothing
 * loaded from the network, so it opens offline and can be attached to a pull request as it is.
 */
final class SignatureGasHtmlReport {

  private static final DateTimeFormatter FILE_TIMESTAMP =
      DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
  private static final DateTimeFormatter SHOWN_TIMESTAMP =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z");

  private static final String STYLE =
      """
      :root {
        color-scheme: light dark;
        --bg: #f7f7f5; --surface: #ffffff; --text: #1d1d1b; --muted: #6b6b66;
        --border: #e2e1dc; --accent: #2f5bd3; --warn-bg: #fff4e0; --warn-text: #8a4b00;
        --base: #b9b8b1; --cpu: #e0703a; --bytes: #2f5bd3;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --bg: #161615; --surface: #1f1f1d; --text: #ecebe6; --muted: #9c9b94;
          --border: #34332f; --accent: #7d9cf0; --warn-bg: #3a2a12; --warn-text: #f3c27a;
          --base: #5c5b55; --cpu: #ec8a59; --bytes: #6f8fec;
        }
      }
      * { box-sizing: border-box; }
      body {
        margin: 0; background: var(--bg); color: var(--text);
        font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      }
      main { max-width: 1200px; margin: 0 auto; padding: 32px 16px 64px; }
      h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
      h2 { font-size: 18px; margin: 0 0 12px; }
      p { margin: 0 0 12px; }
      .subtitle { color: var(--muted); margin-bottom: 24px; }
      section {
        background: var(--surface); border: 1px solid var(--border); border-radius: 10px;
        padding: 20px; margin-bottom: 20px;
      }
      .lead { color: var(--muted); }
      .warning {
        background: var(--warn-bg); color: var(--warn-text); border-radius: 8px;
        padding: 12px 16px; margin-bottom: 20px; font-weight: 600;
      }
      .facts { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 12px 24px; margin: 0; }
      .facts dt { color: var(--muted); font-size: 13px; }
      .facts dd { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
      .table-wrap { overflow-x: auto; }
      table { border-collapse: collapse; width: 100%; font-variant-numeric: tabular-nums; }
      th, td { padding: 8px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; }
      th { font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted);
        text-align: right; font-weight: 600; }
      td { text-align: right; }
      th:first-child, td:first-child { text-align: left; }
      td:first-child { font-weight: 600; }
      tr.baseline td { background: color-mix(in srgb, var(--accent) 8%, transparent); }
      td.strong { font-weight: 700; }
      td.noisy { color: var(--warn-text); background: var(--warn-bg); font-weight: 600; }
      .muted { color: var(--muted); }
      .chart { display: grid; gap: 8px; }
      .chart-row { display: grid; grid-template-columns: 170px minmax(0, 1fr) 80px;
        grid-template-areas: "label bar total"; gap: 4px 12px; align-items: center; }
      .chart .label { grid-area: label; font-weight: 600; font-size: 14px; }
      .chart .bar { grid-area: bar; }
      .chart .total { grid-area: total; text-align: right; font-variant-numeric: tabular-nums;
        font-weight: 600; font-size: 14px; }
      .table-wrap table:not(.terms) { min-width: max-content; }
      .bar { display: flex; height: 18px; border-radius: 4px; overflow: hidden;
        background: var(--border); }
      .bar span { display: block; height: 100%; }
      .seg-base { background: var(--base); }
      .seg-cpu { background: var(--cpu); }
      .seg-bytes { background: var(--bytes); }
      .legend { display: flex; flex-wrap: wrap; gap: 16px; margin-top: 16px; font-size: 13px;
        color: var(--muted); }
      .legend i { display: inline-block; width: 12px; height: 12px; border-radius: 3px;
        margin-right: 6px; vertical-align: -1px; }
      .formula { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        background: var(--bg); border: 1px solid var(--border); border-radius: 8px;
        padding: 12px 16px; margin: 0 0 16px; overflow-x: auto; white-space: pre; font-size: 14px; }
      .terms td { white-space: normal; text-align: left; vertical-align: top; }
      .terms td:first-child { white-space: nowrap; font-family: ui-monospace, Menlo, monospace;
        font-weight: 600; }
      ul.notes { margin: 0; padding-left: 20px; }
      ul.notes li { margin-bottom: 6px; }
      footer { color: var(--muted); font-size: 13px; text-align: center; }
      @media (max-width: 600px) {
        .chart-row { grid-template-columns: minmax(0, 1fr) max-content;
          grid-template-areas: "label total" "bar bar"; }
        th, td { padding: 6px 8px; }
      }
      """;

  private SignatureGasHtmlReport() {}

  /**
   * Writes the report to a new file in the directory, named after the time the report was made.
   *
   * @return the file written
   */
  static Path write(final Report report, final Path directory) throws IOException {
    Files.createDirectories(directory);
    final Path file =
        directory.resolve(
            "signature-gas-report-" + FILE_TIMESTAMP.format(report.createdAt()) + ".html");
    Files.writeString(file, render(report), StandardCharsets.UTF_8);
    return file;
  }

  static String render(final Report report) {
    final StringBuilder html = new StringBuilder();
    html.append("<!doctype html>\n<html lang=\"en\">\n<head>\n")
        .append("<meta charset=\"utf-8\">\n")
        .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
        .append("<title>Signature gas report</title>\n")
        .append("<style>\n")
        .append(STYLE)
        .append("</style>\n</head>\n<body>\n<main>\n");

    html.append("<h1>Signature gas report</h1>\n")
        .append("<p class=\"subtitle\">Gas a flexible transaction would pay for its signature")
        .append(" under the proposed model, per DSA type, measured on ")
        .append(escape(SHOWN_TIMESTAMP.format(report.createdAt())))
        .append(".</p>\n");

    if (!report.nativeSecp256k1()) {
      html.append("<div class=\"warning\">The secp256k1 baseline ran on the Java implementation,")
          .append(" so every relative gas value is far too low. Do not use these numbers for")
          .append(" pricing.</div>\n");
    }

    appendRun(html, report);
    appendChart(html, report);
    appendMeasurements(html, report);
    appendTotalGas(html, report);
    appendNotes(html, report);

    html.append("<footer><p>Produced by <code>")
        .append(SignatureGasReport.class.getSimpleName())
        .append("</code> from <code>")
        .append(SignatureCostBenchmark.class.getSimpleName())
        .append("</code>.</p>\n<p>Generated by Venturus with the help of Claude Code.</p>")
        .append("</footer>\n</main>\n</body>\n</html>\n");
    return html.toString();
  }

  private static void appendRun(final StringBuilder html, final Report report) {
    final BenchmarkParams params = report.params();
    html.append("<section>\n<h2>Run</h2>\n<dl class=\"facts\">\n");
    fact(html, "Baseline (SECP256K1)", time(report.baseline().getScore(), report.unit()));
    fact(html, "SECP256K1", SignatureGasReport.implementation(report.nativeSecp256k1()));
    fact(html, "SECP256R1", SignatureGasReport.implementation(report.nativeSecp256r1()));
    fact(
        html,
        "Iterations",
        String.format(
            Locale.ROOT,
            "%d forks × %d × %s (warmup %d × %s)",
            params.getForks(),
            params.getMeasurement().getCount(),
            params.getMeasurement().getTime(),
            params.getWarmup().getCount(),
            params.getWarmup().getTime()));
    fact(html, "JVM", params.getVmName() + " " + params.getVmVersion());
    fact(html, "JMH", params.getJmhVersion());
    fact(
        html,
        "Machine",
        System.getProperty("os.name")
            + " "
            + System.getProperty("os.arch")
            + ", "
            + Runtime.getRuntime().availableProcessors()
            + " CPUs");
    cpuModel().ifPresent(model -> fact(html, "CPU", model));
    html.append("</dl>\n</section>\n");
  }

  private static void appendChart(final StringBuilder html, final Report report) {
    final long maxTotal = report.rows().stream().mapToLong(Row::totalGas).max().orElse(1);
    html.append("<section>\n<h2>Total gas per DSA type</h2>\n")
        .append("<p class=\"lead\">What replaces the 21,000 base gas of a legacy transaction.")
        .append(" Most of it pays for the bytes the transaction carries, not for the CPU.</p>\n")
        .append("<div class=\"chart\">\n");
    for (final Row row : report.rows()) {
      final long bytesGas = row.footprint().bytesGas();
      html.append("<div class=\"chart-row\"><div class=\"label\">")
          .append(escape(row.dsaType().getName()))
          .append("</div>\n<div class=\"bar\" role=\"img\" aria-label=\"")
          .append(
              escape(
                  String.format(
                      Locale.ROOT,
                      "%s: base %,d, CPU %,d, bytes %,d gas",
                      row.dsaType().getName(),
                      FLEXIBLE_BASE_GAS,
                      row.relativeGas(),
                      bytesGas)))
          .append("\">");
      segment(html, "seg-base", "base", FLEXIBLE_BASE_GAS, maxTotal);
      segment(html, "seg-cpu", "CPU", row.relativeGas(), maxTotal);
      segment(html, "seg-bytes", "bytes", bytesGas, maxTotal);
      html.append("</div>\n<div class=\"total\">")
          .append(gas(row.totalGas()))
          .append("</div></div>\n");
    }
    html.append("</div>\n<div class=\"legend\">")
        .append("<span><i class=\"seg-base\"></i>base ")
        .append(gas(FLEXIBLE_BASE_GAS))
        .append("</span>")
        .append("<span><i class=\"seg-cpu\"></i>CPU (gas relative)</span>")
        .append("<span><i class=\"seg-bytes\"></i>signature and key bytes</span>")
        .append("</div>\n</section>\n");
  }

  private static void segment(
      final StringBuilder html,
      final String cssClass,
      final String name,
      final long value,
      final long maxTotal) {
    html.append(
        String.format(
            Locale.ROOT,
            "<span class=\"%s\" style=\"width:%.3f%%\" title=\"%s: %,d gas\"></span>",
            cssClass,
            100D * value / maxTotal,
            name,
            value));
  }

  private static void appendMeasurements(final StringBuilder html, final Report report) {
    html.append("<section>\n<h2>Measurements</h2>\n")
        .append("<p class=\"lead\">Average time to authenticate one signature: a key recovery for")
        .append(" recoverable algorithms, a verification for the others, and each half by its own")
        .append(" rule for hybrids. The error is the half-width of the 99.9% confidence")
        .append(" interval.</p>\n")
        .append("<div class=\"formula\">")
        .append(
            escape(
                String.format(
                    Locale.ROOT,
                    "gas (relative) = %,d gas × time / time(SECP256K1)        anchored at"
                        + " ECRECOVER%n"
                        + "gas (absolute) = %,.0f gas × time / time(SECP256K1)        where %,.0f gas = %.3f %s ×"
                        + " %,d gas/s (1 gas = 10 ns)",
                    ECRECOVER_GAS,
                    report.baselineAbsoluteGas(),
                    report.baselineAbsoluteGas(),
                    report.baseline().getScore(),
                    report.unit(),
                    GAS_PER_SECOND)))
        .append("</div>\n<div class=\"table-wrap\">\n<table>\n<thead><tr>")
        .append("<th>dsaType</th><th>time (")
        .append(escape(report.unit()))
        .append(")</th><th>± error</th><th>min – max</th><th>ratio</th><th>gas (relative)</th>")
        .append("<th>conserv. (rel.)</th><th>gas (absolute)</th><th>total gas</th>")
        .append("</tr></thead>\n<tbody>\n");
    for (final Row row : report.rows()) {
      html.append(row.dsaType() == DSAParametersSet.SECP256K1 ? "<tr class=\"baseline\">" : "<tr>")
          .append("<td>")
          .append(escape(row.dsaType().getName()))
          .append("</td><td>")
          .append(String.format(Locale.ROOT, "%.3f", row.result().getScore()))
          .append("</td>")
          .append(errorCell(row))
          .append("<td class=\"muted\">")
          .append(
              String.format(
                  Locale.ROOT,
                  "%.1f – %.1f",
                  row.result().getStatistics().getMin(),
                  row.result().getStatistics().getMax()))
          .append("</td><td>")
          .append(String.format(Locale.ROOT, "%.2f", row.ratio()))
          .append("</td><td>")
          .append(gas(row.relativeGas()))
          .append("</td><td>")
          .append(gas(row.conservativeGas()))
          .append("</td><td>")
          .append(gas(row.absoluteGas()))
          .append("</td><td class=\"strong\">")
          .append(gas(row.totalGas()))
          .append("</td></tr>\n");
    }
    for (final DSAParametersSet dsaType : report.missing()) {
      html.append("<tr><td>")
          .append(escape(dsaType.getName()))
          .append("</td><td colspan=\"8\" class=\"muted\">no result</td></tr>\n");
    }
    html.append("</tbody>\n</table>\n</div>\n</section>\n");
  }

  private static String errorCell(final Row row) {
    final OptionalDouble error = row.error();
    if (error.isEmpty()) {
      return "<td class=\"muted\">n/a</td>";
    }
    return String.format(
        Locale.ROOT,
        "<td%s>%.3f <span class=\"muted\">(%.1f%%)</span></td>",
        row.isNoisy() ? " class=\"noisy\" title=\"High error: see the notes\"" : "",
        error.getAsDouble(),
        100 * row.relativeError().orElseThrow());
  }

  private static void appendTotalGas(final StringBuilder html, final Report report) {
    html.append("<section>\n<h2>How the total gas is computed</h2>\n")
        .append("<p>The total gas is what a flexible transaction would pay for its signature under")
        .append(
            " this model, in place of the 21,000 base gas of a legacy transaction. It is a fixed worst case per")
        .append(" dsaType, so it is known before the transaction is signed: the gas limit is part")
        .append(" of what gets signed, and a Falcon signature changes length every time it is")
        .append(" produced.</p>\n")
        .append("<div class=\"formula\">")
        .append(
            escape(
                String.format(
                    Locale.ROOT,
                    "total gas = %,d − %,d − %d × %d + gas (relative) + %d × (signature bytes + key"
                        + " bytes)%n"
                        + "          = %,d + gas (relative) + %d × (signature bytes + key bytes)",
                    TRANSACTION_BASE_GAS,
                    ECRECOVER_GAS,
                    ECDSA_SIGNATURE_BYTES,
                    GAS_PER_BYTE,
                    GAS_PER_BYTE,
                    FLEXIBLE_BASE_GAS,
                    GAS_PER_BYTE)))
        .append("</div>\n<div class=\"table-wrap\">\n<table class=\"terms\">\n<tbody>\n");
    term(
        html,
        gas(TRANSACTION_BASE_GAS),
        "Base gas of every transaction. It already pays for one ECDSA signature: recovering the"
            + " signer from it, and carrying its bytes.");
    term(
        html,
        "− " + gas(ECRECOVER_GAS),
        "The recovery of that signature, priced as the ECRECOVER precompile, which runs the same"
            + " recovery. The algorithm's own CPU cost replaces it.");
    term(
        html,
        String.format(Locale.ROOT, "− %d × %d", ECDSA_SIGNATURE_BYTES, GAS_PER_BYTE),
        String.format(
            Locale.ROOT,
            "The %d bytes of r, s and v of that signature (%,d gas). The bytes the flexible"
                + " transaction carries replace them.",
            ECDSA_SIGNATURE_BYTES,
            ECDSA_SIGNATURE_BYTES * GAS_PER_BYTE));
    term(
        html,
        "gas (relative)",
        "CPU cost of authenticating the signature, from the measurements above.");
    term(
        html,
        Long.toString(GAS_PER_BYTE),
        String.format(
            Locale.ROOT,
            "Gas per byte, the price of a non-zero calldata byte (EIP-2028). Zero bytes cost %d,"
                + " but signatures and keys are close to random and their bytes are not known"
                + " before signing, so every byte is priced as non-zero.",
            GAS_PER_ZERO_BYTE));
    term(
        html,
        "signature bytes",
        "The algorithm's signature length. Falcon signatures vary in length, so their maximum is"
            + " used; a hybrid adds the lengths of its two halves.");
    term(
        html,
        "key bytes",
        "The public key the transaction carries. A key that can be recovered from the signature"
            + " is not carried (0). A hybrid carries only the key of its half that cannot be"
            + " recovered.");
    html.append("</tbody>\n</table>\n</div>\n")
        .append("<p class=\"lead\" style=\"margin-top:16px\">Not included: calldata, access list,")
        .append(" code delegations and contract creation, which are charged as for any other")
        .append(" transaction. The dsaType field and the length prefixes around the signature and")
        .append(" the key are left out too: a few bytes each, negligible next to what they")
        .append(" frame.</p>\n")
        .append("<div class=\"table-wrap\">\n<table>\n<thead><tr>")
        .append("<th>dsaType</th><th>sig bytes</th><th>key bytes</th><th>bytes gas</th>")
        .append("<th>CPU gas</th><th>total gas</th></tr></thead>\n<tbody>\n");
    for (final Row row : report.rows()) {
      html.append("<tr><td>")
          .append(escape(row.dsaType().getName()))
          .append("</td><td>")
          .append(gas(row.footprint().signatureBytes()))
          .append("</td><td>")
          .append(gas(row.footprint().keyBytes()))
          .append("</td><td>")
          .append(gas(row.footprint().bytesGas()))
          .append("</td><td>")
          .append(gas(row.relativeGas()))
          .append("</td><td class=\"strong\">")
          .append(gas(row.totalGas()))
          .append("</td></tr>\n");
    }
    html.append("</tbody>\n</table>\n</div>\n</section>\n");
  }

  private static void appendNotes(final StringBuilder html, final Report report) {
    if (report.notes().isEmpty()) {
      return;
    }
    html.append("<section>\n<h2>Notes</h2>\n<ul class=\"notes\">\n");
    for (final String note : report.notes()) {
      html.append("<li>").append(escape(note)).append("</li>\n");
    }
    html.append("</ul>\n</section>\n");
  }

  private static void fact(final StringBuilder html, final String name, final String value) {
    html.append("<div><dt>")
        .append(escape(name))
        .append("</dt><dd>")
        .append(escape(value))
        .append("</dd></div>\n");
  }

  private static void term(final StringBuilder html, final String term, final String meaning) {
    html.append("<tr><td>")
        .append(escape(term))
        .append("</td><td>")
        .append(escape(meaning))
        .append("</td></tr>\n");
  }

  private static String gas(final long gas) {
    return String.format(Locale.ROOT, "%,d", gas);
  }

  private static String gas(final OptionalLong gas) {
    return gas.isPresent() ? gas(gas.getAsLong()) : "n/a";
  }

  private static String time(final double score, final String unit) {
    return String.format(Locale.ROOT, "%.3f %s", score, unit);
  }

  /** The CPU model on Linux, to tell apart reports from different machines. */
  private static Optional<String> cpuModel() {
    try (Stream<String> lines = Files.lines(Path.of("/proc/cpuinfo"))) {
      return lines
          .filter(line -> line.startsWith("model name"))
          .map(line -> line.substring(line.indexOf(':') + 1).trim())
          .findFirst();
    } catch (final IOException | RuntimeException e) {
      return Optional.empty();
    }
  }

  private static String escape(final String text) {
    return text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;");
  }
}
