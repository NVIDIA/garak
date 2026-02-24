import { renderHook } from "@testing-library/react";
import useSeverityColor from "../useSeverityColor";
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock getComputedStyle
beforeEach(() => {
    const colorMap: Record<string, string> = {
    "--color-teal-200": "#7dd3fc",
    "--color-teal-400": "#2dd4bf",
    "--color-green-200": "#bbf7d0",
    "--color-green-400": "#4ade80",
    "--color-green-600": "#16a34a",
    "--color-blue-200": "#bfdbfe",
    "--color-blue-400": "#60a5fa",
    "--color-yellow-200": "#fef08a",
    "--color-yellow-300": "#fde047",
    "--color-yellow-400": "#facc15",
    "--color-red-200": "#fecaca",
    "--color-gray-200": "#e5e7eb",
    "--color-red-700": "#b91c1c",
    "--color-red-400": "#f87171",
    };

  vi.stubGlobal("getComputedStyle", () => ({
    getPropertyValue: (prop: string) => colorMap[prop] || "",
  }));
});

describe("useSeverityColor", () => {
  it("returns correct color for severity level", () => {
    const { result } = renderHook(() => useSeverityColor());

    expect(result.current.getSeverityColorByLevel(5)).toBe("#7dd3fc"); // teal-200
    expect(result.current.getSeverityColorByLevel(4)).toBe("#4ade80"); // green-400
    expect(result.current.getSeverityColorByLevel(3)).toBe("#bfdbfe"); // blue-200
    expect(result.current.getSeverityColorByLevel(2)).toBe("#fef08a"); // yellow-200
    expect(result.current.getSeverityColorByLevel(1)).toBe("#fecaca"); // red-200
    expect(result.current.getSeverityColorByLevel(0)).toBe("#e5e7eb"); // gray-200
  });

  it("returns correct color for severity comment", () => {
    const { result } = renderHook(() => useSeverityColor());

    expect(result.current.getSeverityColorByComment("very poor")).toBe("#fecaca"); // red-200
    expect(result.current.getSeverityColorByComment("poor")).toBe("#fecaca"); // red-200
    expect(result.current.getSeverityColorByComment("below average")).toBe("#fef08a"); // yellow-200
    expect(result.current.getSeverityColorByComment("average")).toBe("#bfdbfe"); // blue-200 (DC-3)
    expect(result.current.getSeverityColorByComment("above average")).toBe("#bfdbfe"); // blue-200 (DC-3)
    expect(result.current.getSeverityColorByComment("excellent")).toBe("#7dd3fc"); // teal-200
    expect(result.current.getSeverityColorByComment("competitive")).toBe("#7dd3fc"); // teal-200
    expect(result.current.getSeverityColorByComment("nonsense")).toBe("#e5e7eb"); // gray-200
    expect(result.current.getSeverityColorByComment(undefined)).toBe("#e5e7eb"); // gray-200
  });

  it("returns correct defcon color", () => {
    const { result } = renderHook(() => useSeverityColor());

    expect(result.current.getDefconColor(1)).toBe("#b91c1c"); // red-700
    expect(result.current.getDefconColor(2)).toBe("#facc15"); // yellow-400
    expect(result.current.getDefconColor(3)).toBe("#60a5fa"); // blue-400
    expect(result.current.getDefconColor(4)).toBe("#16a34a"); // green-600
    expect(result.current.getDefconColor(5)).toBe("#2dd4bf"); // teal-400
    expect(result.current.getDefconColor(undefined)).toBe("#16a34a"); // green-600 (default to DC-4)
  });

  it("returns correct severity label", () => {
    const { result } = renderHook(() => useSeverityColor());

    expect(result.current.getSeverityLabelByLevel(1)).toBe("Critical Risk");
    expect(result.current.getSeverityLabelByLevel(2)).toBe("Very High Risk");
    expect(result.current.getSeverityLabelByLevel(3)).toBe("Elevated Risk");
    expect(result.current.getSeverityLabelByLevel(4)).toBe("Medium Risk");
    expect(result.current.getSeverityLabelByLevel(5)).toBe("Low Risk");
    expect(result.current.getSeverityLabelByLevel(null)).toBe("Unknown");
  });

  it("returns correct badge colors", () => {
    const { result } = renderHook(() => useSeverityColor());

    expect(result.current.getDefconBadgeColor(1)).toBe("red");
    expect(result.current.getDefconBadgeColor(2)).toBe("yellow");
    expect(result.current.getDefconBadgeColor(3)).toBe("blue"); // distinct from DC-4
    expect(result.current.getDefconBadgeColor(4)).toBe("green");
    expect(result.current.getDefconBadgeColor(5)).toBe("teal");
    expect(result.current.getDefconBadgeColor(0)).toBe("gray");
  });
});
