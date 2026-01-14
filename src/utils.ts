import crypto from "crypto";
import fs from "fs";
import path from "path";

export const DEFAULT_IGNORES = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/.turbo/**",
  "**/.expo/**",
  "**/coverage/**",
  "**/.cache/**",
  "**/vendor/**",
  "**/pods/**",
  "**/DerivedData/**"
];

export const TEXT_EXTENSIONS = new Set([
  ".js",
  ".ts",
  ".tsx",
  ".jsx",
  ".json",
  ".env",
  ".yml",
  ".yaml",
  ".toml",
  ".py",
  ".rb",
  ".go",
  ".java",
  ".kt",
  ".swift",
  ".php",
  ".html",
  ".css",
  ".md",
  ".txt"
]);

export const DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024;

export function normalizePath(filePath: string): string {
  return filePath.split(path.sep).join("/");
}

export function sha256(value: string): string {
  const hash = crypto.createHash("sha256").update(value).digest("hex");
  return `sha256:${hash}`;
}

export function maskSecret(value: string): string {
  if (!value) {
    return "****";
  }
  const last4 = value.slice(-4);
  return `****${last4}`;
}

export function maskInContext(line: string, secret: string, masked: string): string {
  if (!secret) {
    return line;
  }
  return line.split(secret).join(masked);
}

export function shannonEntropy(value: string): number {
  if (!value) {
    return 0;
  }
  const counts = new Map<string, number>();
  for (const ch of value) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function isBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8000));
  for (const byte of sample) {
    if (byte === 0) {
      return true;
    }
  }
  return false;
}

export function looksLikeText(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".env") {
    return true;
  }
  if (TEXT_EXTENSIONS.has(ext)) {
    return true;
  }
  const base = path.basename(filePath).toLowerCase();
  if (base === ".env" || base.startsWith(".env.")) {
    return true;
  }
  return false;
}

export function safeReadFile(filePath: string): Buffer | null {
  try {
    return fs.readFileSync(filePath);
  } catch {
    return null;
  }
}
