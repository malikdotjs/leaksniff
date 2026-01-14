import fs from "fs";
import path from "path";
import { afterAll, describe, expect, it } from "vitest";
import { buildIgnoreMatcher, shouldIgnorePath } from "../src/scanner.js";

describe("ignore patterns", () => {
  const ignoreFile = path.join(process.cwd(), "tests", "tmp-ignore.txt");

  afterAll(() => {
    if (fs.existsSync(ignoreFile)) {
      fs.unlinkSync(ignoreFile);
    }
  });

  it("respects gitignore-style patterns", () => {
    fs.writeFileSync(ignoreFile, "secrets/*.env\n");
    const ig = buildIgnoreMatcher(ignoreFile);
    expect(shouldIgnorePath("secrets/prod.env", ig)).toBe(true);
    expect(shouldIgnorePath("src/app.ts", ig)).toBe(false);
  });
});
