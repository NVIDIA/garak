import { renderHook } from "@testing-library/react";
import { useValueFormatter } from "../useValueFormatter";
import { describe, it, expect } from "vitest";

describe("useValueFormatter", () => {
  const { result } = renderHook(() => useValueFormatter());

  it("formats arrays", () => {
    expect(result.current.formatValue(["a", "b", "c"])).toBe("a, b, c");
  });

  it("formats booleans", () => {
    expect(result.current.formatValue(true)).toBe("Enabled");
    expect(result.current.formatValue(false)).toBe("Disabled");
  });

  it("formats null/undefined", () => {
    expect(result.current.formatValue(null)).toBe("N/A");
    expect(result.current.formatValue(undefined)).toBe("N/A");
  });

  it("formats strings and numbers as-is", () => {
    expect(result.current.formatValue("hello")).toBe("hello");
    expect(result.current.formatValue(123)).toBe("123");
  });

  it("formats objects as compact JSON (not '[object Object]')", () => {
    expect(result.current.formatValue({ a: 1 })).toBe('{"a":1}');
    expect(result.current.formatValue({ include: ["probes.dan"] })).toBe(
      '{"include":["probes.dan"]}',
    );
  });

  it("formats other primitives via String()", () => {
    expect(result.current.formatValue(Symbol("x"))).toBe("Symbol(x)");
  });
});
