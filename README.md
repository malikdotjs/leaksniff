# leaksniff

Smell secrets before attackers do. leaksniff is a fast, local-first CLI that scans your repo for hardcoded API keys, tokens, and credentials with low false positives.

## Install

```bash
npm i -g leaksniff
# or
npx leaksniff .
```

## Quickstart

```bash
leaksniff .
leaksniff ./apps/api --severity high --progress
leaksniff . --json --out report.json --redact
leaksniff . --ignore-file .secret-scan-ignore --ignore-regex "dummy" --max-findings 20
```

## JSON output

```json
{
  "tool": "leaksniff",
  "version": "0.1.0",
  "scannedPath": "/abs/path",
  "summary": { "filesScanned": 120, "findings": 2, "durationMs": 534 },
  "findings": [
    {
      "severity": "high",
      "type": "stripe_live_key",
      "file": "src/config.ts",
      "line": 12,
      "column": 15,
      "matchPreview": "****ABCD",
      "hash": "sha256:...",
      "context": "const stripeKey = '****ABCD'",
      "ruleId": "STRIPE_LIVE",
      "confidence": 92
    }
  ]
}
```

## Exit codes

- `0`: No secrets found
- `1`: Secrets found
- `2`: Error (invalid args or IO)

## Ignore file format

`.secret-scan-ignore` uses simple gitignore-style glob patterns:

```text
# ignore build artifacts
build/
dist/
# ignore specific files
.env.local
secrets/*.env
```

## Safety

- Console output never prints full secrets; it masks to the last 4 characters.
- JSON output includes masked values by default; use `--redact` to fully redact values and context.

## Disclaimer

- This is a best-effort scanner; it may miss secrets or flag false positives.
- Always rotate credentials if you suspect exposure.
- The tool is local-only and does not make network calls.

## Development

```bash
pnpm install
pnpm run dev -- .
pnpm run build
pnpm test
pnpm run lint
```
