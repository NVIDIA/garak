import { renderHook } from "@testing-library/react";
import useSeverityColor from "../useSeverityColor";
import { describe, it, expect, vi } from "vitest";

// Mock the getColor function from @kui/foundations
vi.mock("@kui/foundations", () => ({
  getColor: vi.fn((colorToken: string) => {
    const colorMap: Record<string, string> = {
      "--teal-200": "#7dd3fc",
      "--green-200": "#bbf7d0", 
      "--yellow-200": "#fef08a",
      "--red-200": "#fecaca",
      "--gray-200": "#e5e7eb",
      "--red-700": "#b91c1c",
      "--red-400": "#f87171",
      "--green-400": "#4ade80",
      "--teal-400": "#2dd4bf",
    };
    return colorMap[colorToken] || "#000000";
  }),
}));

describe("useSeverityColor", () => {
  const { result } = renderHook(() => useSeverityColor());

  it("returns correct color for severity level", () => {
    expect(result.current.getSeverityColorByLevel(5)).toBe("#7dd3fc"); // teal-200
    expect(result.current.getSeverityColorByLevel(4)).toBe("#bbf7d0"); // green-200
    expect(result.current.getSeverityColorByLevel(3)).toBe("#bbf7d0"); // green-200
    expect(result.current.getSeverityColorByLevel(2)).toBe("#fef08a"); // yellow-200
    expect(result.current.getSeverityColorByLevel(1)).toBe("#fecaca"); // red-200
    expect(result.current.getSeverityColorByLevel(0)).toBe("#e5e7eb"); // gray-200
  });

  it("returns correct color for severity comment", () => {
    expect(result.current.getSeverityColorByComment("very poor")).toBe("#fecaca"); // red-200
    expect(result.current.getSeverityColorByComment("poor")).toBe("#fecaca"); // red-200
    expect(result.current.getSeverityColorByComment("below average")).toBe("#fef08a"); // yellow-200
    expect(result.current.getSeverityColorByComment("average")).toBe("#bbf7d0"); // green-200
    expect(result.current.getSeverityColorByComment("above average")).toBe("#bbf7d0"); // green-200
    expect(result.current.getSeverityColorByComment("excellent")).toBe("#7dd3fc"); // teal-200
    expect(result.current.getSeverityColorByComment("competitive")).toBe("#7dd3fc"); // teal-200
    expect(result.current.getSeverityColorByComment("nonsense")).toBe("#e5e7eb"); // gray-200
    expect(result.current.getSeverityColorByComment(undefined)).toBe("#e5e7eb"); // gray-200
  });

  it("returns correct defcon color", () => {
    expect(result.current.getDefconColor(1)).toBe("#b91c1c"); // red-700
    expect(result.current.getDefconColor(2)).toBe("#f87171"); // red-400
    expect(result.current.getDefconColor(3)).toBe("#fef08a"); // yellow-200
    expect(result.current.getDefconColor(4)).toBe("#4ade80"); // green-400
    expect(result.current.getDefconColor(5)).toBe("#2dd4bf"); // teal-400
    expect(result.current.getDefconColor(undefined)).toBe("#4ade80"); // green-400 (default)
  });

  it("returns correct severity label", () => {
    expect(result.current.getSeverityLabelByLevel(1)).toBe("Critical");
    expect(result.current.getSeverityLabelByLevel(2)).toBe("Poor");
    expect(result.current.getSeverityLabelByLevel(3)).toBe("Average");
    expect(result.current.getSeverityLabelByLevel(4)).toBe("Good");
    expect(result.current.getSeverityLabelByLevel(5)).toBe("Excellent");
    expect(result.current.getSeverityLabelByLevel(null)).toBe("Unknown");
  });

  it("returns correct badge colors", () => {
    expect(result.current.getDefconBadgeColor(1)).toBe("red");
    expect(result.current.getDefconBadgeColor(2)).toBe("yellow");
    expect(result.current.getDefconBadgeColor(3)).toBe("green");
    expect(result.current.getDefconBadgeColor(4)).toBe("green");
    expect(result.current.getDefconBadgeColor(5)).toBe("teal");
    expect(result.current.getDefconBadgeColor(0)).toBe("gray");
  });
});
