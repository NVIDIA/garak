import { renderHook } from "@testing-library/react";
import { useZScoreHelpers } from "../useZScoreHelpers";
import { describe, it, expect } from "vitest";

describe("useZScoreHelpers", () => {
  const { result } = renderHook(() => useZScoreHelpers());

  describe("formatZ", () => {
    it("returns 'N/A' for null", () => {
      expect(result.current.formatZ(null)).toBe("N/A");
    });

    it("formats normal values with 2 decimals", () => {
      expect(result.current.formatZ(0)).toBe("0.00");
      expect(result.current.formatZ(1.2345)).toBe("1.23");
      expect(result.current.formatZ(-2.5)).toBe("-2.50");
    });

    it("returns capped labels for extreme values", () => {
      expect(result.current.formatZ(-3)).toBe("≤ -3.0");
      expect(result.current.formatZ(-10)).toBe("≤ -3.0");
      expect(result.current.formatZ(3)).toBe("≥ 3.0");
      expect(result.current.formatZ(5.5)).toBe("≥ 3.0");
    });
  });

  describe("clampZ", () => {
    it("clamps below -3 to -3", () => {
      expect(result.current.clampZ(-10)).toBe(-3);
    });

    it("clamps above 3 to 3", () => {
      expect(result.current.clampZ(5)).toBe(3);
    });

    it("passes through valid range", () => {
      expect(result.current.clampZ(-2)).toBe(-2);
      expect(result.current.clampZ(0)).toBe(0);
      expect(result.current.clampZ(2.9)).toBe(2.9);
    });
  });
});
