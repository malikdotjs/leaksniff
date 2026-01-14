import path from "path";
import Table from "cli-table3";
import chalk from "chalk";
import type { Finding } from "./scanner.js";
import { normalizePath } from "./utils.js";

export type ScanSummary = {
  filesScanned: number;
  findings: number;
  durationMs: number;
};

export type JsonReport = {
  tool: string;
  version: string;
  scannedPath: string;
  summary: ScanSummary;
  findings: Finding[];
};

function severityColor(severity: Finding["severity"]): (text: string) => string {
  if (severity === "high") {
    return chalk.red;
  }
  if (severity === "med") {
    return chalk.yellow;
  }
  return chalk.blue;
}

export function formatConsoleTable(findings: Finding[]): string {
  if (findings.length === 0) {
    return chalk.green("No secrets detected.");
  }

  const table = new Table({
    head: [
      chalk.bold("Severity"),
      chalk.bold("Type"),
      chalk.bold("File"),
      chalk.bold("Line"),
      chalk.bold("Match"),
      chalk.bold("Hash")
    ],
    colWidths: [10, 20, 40, 8, 14, 74],
    wordWrap: true
  });

  for (const finding of findings) {
    const color = severityColor(finding.severity);
    table.push([
      color(finding.severity.toUpperCase()),
      finding.type,
      finding.file,
      String(finding.line),
      finding.matchPreview,
      finding.hash
    ]);
  }

  return table.toString();
}

export function toJsonReport(
  findings: Finding[],
  summary: ScanSummary,
  scannedPath: string,
  version: string,
  redact: boolean
): JsonReport {
  const normalizedPath = normalizePath(path.resolve(scannedPath));
  const adjustedFindings = redact
    ? findings.map((finding) => ({
        ...finding,
        matchPreview: "REDACTED",
        context: "REDACTED"
      }))
    : findings;

  return {
    tool: "leaksniff",
    version,
    scannedPath: normalizedPath,
    summary,
    findings: adjustedFindings
  };
}
