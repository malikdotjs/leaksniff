import fs from "fs";
import path from "path";
import fg from "fast-glob";
import ignore, { Ignore } from "ignore";
import pLimit from "p-limit";
import {
  DEFAULT_IGNORES,
  isBinary,
  looksLikeText,
  maskInContext,
  maskSecret,
  normalizePath,
  safeReadFile,
  shannonEntropy,
  sha256
} from "./utils.js";

export type Severity = "low" | "med" | "high";

export type Finding = {
  severity: Severity;
  type: string;
  file: string;
  line: number;
  column: number;
  matchPreview: string;
  hash: string;
  context: string;
  ruleId: string;
  confidence: number;
};

export type ScanOptions = {
  root: string;
  maxFileSize: number;
  maxFindings?: number;
  severity: Severity;
  entropyThreshold: number;
  ignoreFile?: string;
  ignoreRegexes: RegExp[];
  progress?: boolean;
};

type ScanStats = {
  filesScanned: number;
  findings: number;
};

type Rule = {
  id: string;
  type: string;
  severity: Severity;
  regex: RegExp;
  secretGroup?: number;
  requireEntropy?: boolean;
  isJwt?: boolean;
  confidenceBoost?: number;
};

const CONTEXT_KEYWORDS = [
  "secret",
  "token",
  "api key",
  "apikey",
  "bearer",
  "authorization",
  "private",
  "credential"
];

const NEGATIVE_KEYWORDS = [
  "example",
  "dummy",
  "testkey",
  "test key",
  "fixture",
  "mock"
];

const RULES: Rule[] = [
  {
    id: "STRIPE_LIVE",
    type: "stripe_live_key",
    severity: "high",
    regex: /(sk_live|rk_live|pk_live)_[0-9a-zA-Z]{10,}/g
  },
  {
    id: "AWS_ACCESS_KEY_ID",
    type: "aws_access_key",
    severity: "high",
    regex: /(A3T|AKIA|ASIA|AGPA|AIDA|ANPA|AROA|AIPA)[0-9A-Z]{16}/g
  },
  {
    id: "GITHUB_TOKEN",
    type: "github_token",
    severity: "high",
    regex: /(ghp|gho|ghs|ghu)_[A-Za-z0-9]{36,}/g
  },
  {
    id: "OPENAI_KEY",
    type: "openai_key",
    severity: "high",
    regex: /sk-[A-Za-z0-9]{20,}/g
  },
  {
    id: "SUPABASE_URL",
    type: "supabase_url",
    severity: "low",
    regex: /https?:\/\/[a-z0-9-]+\.supabase\.co/gi
  },
  {
    id: "FIREBASE_SERVICE_ACCOUNT",
    type: "firebase_service_account",
    severity: "high",
    regex: /"type"\s*:\s*"service_account"/gi
  },
  {
    id: "FIREBASE_PRIVATE_KEY",
    type: "firebase_private_key",
    severity: "high",
    regex: /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/gi
  },
  {
    id: "JWT_TOKEN",
    type: "jwt_token",
    severity: "med",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    requireEntropy: true,
    isJwt: true
  },
  {
    id: "GENERIC_SECRET",
    type: "generic_secret",
    severity: "low",
    regex: /(password|secret|token|api_key)\s*[:=]\s*(["']?)([^"'\s]{4,})\2/gi,
    secretGroup: 3,
    requireEntropy: true
  }
];

function severityRank(severity: Severity): number {
  if (severity === "high") {
    return 3;
  }
  if (severity === "med") {
    return 2;
  }
  return 1;
}

export function severityEntropyThreshold(severity: Severity): number {
  if (severity === "high") {
    return 0;
  }
  if (severity === "med") {
    return 3.5;
  }
  return 2.5;
}

export function buildIgnoreMatcher(ignoreFilePath?: string): Ignore | null {
  if (!ignoreFilePath) {
    return null;
  }
  if (!fs.existsSync(ignoreFilePath)) {
    return null;
  }
  const content = fs.readFileSync(ignoreFilePath, "utf8");
  const ig = ignore();
  ig.add(content.split(/\r?\n/));
  return ig;
}

export function shouldIgnorePath(relativePath: string, ig?: Ignore | null): boolean {
  if (!ig) {
    return false;
  }
  return ig.ignores(relativePath);
}

export async function listFiles(root: string): Promise<string[]> {
  const patterns = [
    "**/*.js",
    "**/*.ts",
    "**/*.tsx",
    "**/*.jsx",
    "**/*.json",
    "**/*.env",
    "**/.env",
    "**/.env.*",
    "**/*.yml",
    "**/*.yaml",
    "**/*.toml",
    "**/*.py",
    "**/*.rb",
    "**/*.go",
    "**/*.java",
    "**/*.kt",
    "**/*.swift",
    "**/*.php",
    "**/*.html",
    "**/*.css",
    "**/*.md",
    "**/*.txt"
  ];

  return fg(patterns, {
    cwd: root,
    absolute: true,
    dot: true,
    onlyFiles: true,
    followSymbolicLinks: false,
    ignore: DEFAULT_IGNORES
  });
}

function computeContextScore(context: string): number {
  const lower = context.toLowerCase();
  let score = 0;
  if (CONTEXT_KEYWORDS.some((kw) => lower.includes(kw))) {
    score += 10;
  }
  if (NEGATIVE_KEYWORDS.some((kw) => lower.includes(kw))) {
    score -= 20;
  }
  return score;
}

function filePathPenalty(filePath: string): number {
  const lower = filePath.toLowerCase();
  if (/(test|fixture|mock)/.test(lower)) {
    return -20;
  }
  return 0;
}

export function scoreConfidence(
  severity: Severity,
  entropy: number,
  context: string,
  filePath: string,
  boost = 0
): number {
  const base = severity === "high" ? 90 : severity === "med" ? 70 : 40;
  const entropyBonus = Math.min(10, Math.floor(entropy * 2));
  const contextScore = computeContextScore(context);
  const penalty = filePathPenalty(filePath);
  const score = base + entropyBonus + contextScore + penalty + boost;
  return Math.max(0, Math.min(100, score));
}

function getSecretFromMatch(match: RegExpExecArray, rule: Rule): { secret: string; indexOffset: number } {
  if (rule.secretGroup && match[rule.secretGroup]) {
    const secret = match[rule.secretGroup];
    const offset = match[0].indexOf(secret);
    return { secret, indexOffset: offset < 0 ? 0 : offset };
  }
  return { secret: match[0], indexOffset: 0 };
}

export function detectSecretsInText(
  text: string,
  filePath: string,
  options: Pick<ScanOptions, "entropyThreshold" | "ignoreRegexes">
): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    for (const rule of RULES) {
      rule.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = rule.regex.exec(line)) !== null) {
        const { secret, indexOffset } = getSecretFromMatch(match, rule);
        if (!secret) {
          continue;
        }
        if (options.ignoreRegexes.some((rx) => rx.test(secret) || rx.test(line))) {
          continue;
        }
        const entropy = shannonEntropy(secret);
        if (rule.requireEntropy && entropy < options.entropyThreshold) {
          continue;
        }

        let severity = rule.severity;
        let boost = rule.confidenceBoost ?? 0;
        if (rule.isJwt) {
          const lower = line.toLowerCase();
          if (lower.includes("supabase") || lower.includes("service_role")) {
            severity = "high";
            boost += 5;
          }
        }

        const masked = maskSecret(secret);
        const context = maskInContext(line, secret, masked);
        const column = (match.index ?? 0) + indexOffset + 1;

        findings.push({
          severity,
          type: rule.type,
          file: normalizePath(filePath),
          line: i + 1,
          column,
          matchPreview: masked,
          hash: sha256(secret),
          context,
          ruleId: rule.id,
          confidence: scoreConfidence(severity, entropy, line, filePath, boost)
        });
      }
    }
  }

  return findings;
}

export async function scanFile(
  absolutePath: string,
  options: ScanOptions
): Promise<Finding[]> {
  if (!looksLikeText(absolutePath)) {
    return [];
  }
  const stats = fs.statSync(absolutePath);
  if (stats.size > options.maxFileSize) {
    return [];
  }
  const buffer = safeReadFile(absolutePath);
  if (!buffer) {
    return [];
  }
  if (isBinary(buffer)) {
    return [];
  }
  const text = buffer.toString("utf8");
  return detectSecretsInText(text, absolutePath, {
    entropyThreshold: options.entropyThreshold,
    ignoreRegexes: options.ignoreRegexes
  });
}

export async function scanPath(options: ScanOptions): Promise<{ findings: Finding[]; stats: ScanStats }> {
  const files = await listFiles(options.root);
  const ig = buildIgnoreMatcher(options.ignoreFile);

  const limit = pLimit(16);
  let processed = 0;
  let stop = false;
  const stats: ScanStats = { filesScanned: 0, findings: 0 };
  const findings: Finding[] = [];

  const progressInterval = options.progress && process.stdout.isTTY
    ? setInterval(() => {
        process.stdout.write(`\rScanning ${processed}/${files.length} files...`);
      }, 120)
    : null;

  const tasks = files.map((absolutePath) =>
    limit(async () => {
      if (stop) {
        return;
      }
      const relativePath = normalizePath(path.relative(options.root, absolutePath));
      processed += 1;
      if (!relativePath || relativePath.startsWith("..")) {
        return;
      }
      if (shouldIgnorePath(relativePath, ig)) {
        return;
      }
      if (options.ignoreRegexes.some((rx) => rx.test(relativePath))) {
        return;
      }

      const fileFindings = await scanFile(absolutePath, options);
      const filteredFindings = fileFindings.filter(
        (finding) => severityRank(finding.severity) >= severityRank(options.severity)
      );
      if (filteredFindings.length > 0) {
        findings.push(...filteredFindings.map((finding) => ({
          ...finding,
          file: normalizePath(relativePath)
        })));
        stats.findings = findings.length;
        if (options.maxFindings && findings.length >= options.maxFindings) {
          stop = true;
        }
      }
      stats.filesScanned += 1;
    })
  );

  await Promise.all(tasks);

  if (progressInterval) {
    clearInterval(progressInterval);
    process.stdout.write(`\rScanning ${processed}/${files.length} files...done\n`);
  }

  return { findings: findings.slice(0, options.maxFindings ?? findings.length), stats };
}
