/**
 * @file formatPercentage.test.ts
 * @description Tests for formatPercentage utility functions.
 */

import { describe, it, expect } from "vitest";
import { formatPercentage, formatRate } from "../formatPercentage";

describe("formatPercentage", () => {
  it("removes .00 suffix for whole numbers", () => {
    expect(formatPercentage(56)).toBe("56%");
    expect(formatPercentage(100)).toBe("100%");
    expect(formatPercentage(0)).toBe("0%");
  });

  it("keeps decimals when meaningful", () => {
    expect(formatPercentage(18.82)).toBe("18.82%");
    expect(formatPercentage(99.99)).toBe("99.99%");
    expect(formatPercentage(0.01)).toBe("0.01%");
  });

  it("handles edge cases", () => {
    expect(formatPercentage(56.00)).toBe("56%");
    expect(formatPercentage(18.80)).toBe("18.80%");
    expect(formatPercentage(18.08)).toBe("18.08%");
  });

  it("respects custom decimal places", () => {
    expect(formatPercentage(56.123, 3)).toBe("56.123%");
    expect(formatPercentage(56.000, 3)).toBe("56%");
    expect(formatPercentage(56.1, 1)).toBe("56.1%");
    expect(formatPercentage(56.0, 1)).toBe("56%");
  });
});

describe("formatRate", () => {
  it("converts decimal rate to percentage", () => {
    expect(formatRate(0.56)).toBe("56%");
    expect(formatRate(1.0)).toBe("100%");
    expect(formatRate(0)).toBe("0%");
  });

  it("handles rates with decimals", () => {
    expect(formatRate(0.1882)).toBe("18.82%");
    expect(formatRate(0.9999)).toBe("99.99%");
  });
});
