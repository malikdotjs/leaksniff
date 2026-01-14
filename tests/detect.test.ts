import { describe, expect, it } from "vitest";
import { detectSecretsInText } from "../src/scanner.js";

const options = {
  entropyThreshold: 2.5,
  ignoreRegexes: [] as RegExp[]
};

describe("detectSecretsInText", () => {
  it("detects Stripe live keys", () => {
    const text = "const key = 'sk_live_1234567890ABCDEFG';";
    const findings = detectSecretsInText(text, "src/app.ts", options);
    expect(findings.some((f) => f.ruleId === "STRIPE_LIVE")).toBe(true);
  });
});
