import fs from "fs";
import path from "path";
import { Command } from "commander";
import { createRequire } from "module";
import { scanPath, severityEntropyThreshold } from "./scanner.js";
import { DEFAULT_MAX_FILE_SIZE } from "./utils.js";
import { formatConsoleTable, toJsonReport } from "./report.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json");

type CliOptions = {
  json?: boolean;
  out?: string;
  severity: "low" | "med" | "high";
  entropy?: string;
  maxFindings?: string;
  ignoreFile?: string;
  ignoreRegex?: string[];
  progress?: boolean;
  redact?: boolean;
  maxFileSize?: string;
};

function collect(value: string, previous: string[] = []): string[] {
  return previous.concat([value]);
}

const program = new Command();

program
  .name("leaksniff")
  .description("leaksniff - scan a local folder for hardcoded secrets")
  .version(pkg.version)
  .argument("[path]", "path to scan", ".")
  .option("--json", "output JSON to stdout")
  .option("--out <file>", "write JSON report to a file")
  .option("--severity <level>", "severity threshold (low|med|high)", "med")
  .option("--entropy <number>", "entropy threshold override")
  .option("--max-findings <n>", "stop after N findings")
  .option("--ignore-file <path>", "ignore file (gitignore-style)")
  .option("--ignore-regex <pattern>", "regex to suppress matches", collect)
  .option("--progress", "show progress indicator")
  .option("--redact", "fully redact values in JSON")
  .option("--max-file-size <bytes>", "max file size in bytes", String(DEFAULT_MAX_FILE_SIZE))
  .helpOption("--help", "display help for command")
  .parse(process.argv);

const targetPath = program.args[0] ?? ".";
const opts = program.opts<CliOptions>();

async function run(): Promise<void> {
  const root = path.resolve(targetPath);
  if (!fs.existsSync(root)) {
    console.error(`Path not found: ${root}`);
    process.exit(2);
  }

  const severity = opts.severity;
  if (!['low', 'med', 'high'].includes(severity)) {
    console.error(`Invalid severity: ${severity}`);
    process.exit(2);
  }

  const entropyThreshold = opts.entropy ? Number(opts.entropy) : severityEntropyThreshold(severity);
  if (Number.isNaN(entropyThreshold)) {
    console.error("Invalid entropy threshold");
    process.exit(2);
  }

  const maxFindings = opts.maxFindings ? Number(opts.maxFindings) : undefined;
  if (opts.maxFindings && Number.isNaN(maxFindings)) {
    console.error("Invalid max-findings value");
    process.exit(2);
  }

  const maxFileSize = opts.maxFileSize ? Number(opts.maxFileSize) : DEFAULT_MAX_FILE_SIZE;
  if (Number.isNaN(maxFileSize) || maxFileSize <= 0) {
    console.error("Invalid max-file-size value");
    process.exit(2);
  }

  const ignoreRegexes = (opts.ignoreRegex ?? []).map((pattern) => {
    try {
      return new RegExp(pattern);
    } catch {
      console.error(`Invalid ignore-regex pattern: ${pattern}`);
      process.exit(2);
    }
  });

  let ignoreFile = opts.ignoreFile;
  if (!ignoreFile) {
    const defaultIgnore = path.join(root, ".secret-scan-ignore");
    if (fs.existsSync(defaultIgnore)) {
      ignoreFile = defaultIgnore;
    }
  } else if (!path.isAbsolute(ignoreFile)) {
    ignoreFile = path.resolve(root, ignoreFile);
  }

  const start = Date.now();
  const { findings, stats } = await scanPath({
    root,
    maxFileSize,
    maxFindings,
    severity,
    entropyThreshold,
    ignoreFile,
    ignoreRegexes,
    progress: opts.progress
  });
  const durationMs = Date.now() - start;

  const summary = {
    filesScanned: stats.filesScanned,
    findings: findings.length,
    durationMs
  };

  const jsonReport = toJsonReport(findings, summary, root, pkg.version, Boolean(opts.redact));

  if (opts.out) {
    fs.writeFileSync(opts.out, JSON.stringify(jsonReport, null, 2));
  }

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(jsonReport, null, 2)}\n`);
  } else {
    process.stdout.write(`${formatConsoleTable(findings)}\n`);
  }

  process.exit(findings.length > 0 ? 1 : 0);
}

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
});
