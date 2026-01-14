import { describe, expect, it } from "vitest";
import { shannonEntropy } from "../src/utils.js";

describe("shannonEntropy", () => {
  it("returns higher entropy for random strings", () => {
    const low = shannonEntropy("aaaaaaaaaaaaaaaa");
    const high = shannonEntropy("aZ8fK2pQ9xM1sL4t");
    expect(high).toBeGreaterThan(low);
  });
});
