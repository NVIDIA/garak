import { renderHook } from "@testing-library/react";
import useSeverityColor from "../useSeverityColor";
import { describe, it, expect } from "vitest";
import theme from "../../styles/theme";

describe("useSeverityColor", () => {
  const { result } = renderHook(() => useSeverityColor());

  it("returns correct color for severity level", () => {
    expect(result.current.getSeverityColorByLevel(5)).toBe(theme.colors.b400);
    expect(result.current.getSeverityColorByLevel(4)).toBe(theme.colors.g400);
    expect(result.current.getSeverityColorByLevel(3)).toBe(theme.colors.y300);
    expect(result.current.getSeverityColorByLevel(2)).toBe(theme.colors.r400);
    expect(result.current.getSeverityColorByLevel(1)).toBe(theme.colors.r600);
    expect(result.current.getSeverityColorByLevel(0)).toBe(theme.colors.tk150);
  });

  it("returns correct color for severity comment", () => {
    expect(result.current.getSeverityColorByComment("very poor")).toBe(theme.colors.r700);
    expect(result.current.getSeverityColorByComment("poor")).toBe(theme.colors.r400);
    expect(result.current.getSeverityColorByComment("below average")).toBe(theme.colors.y400);
    expect(result.current.getSeverityColorByComment("average")).toBe(theme.colors.g400);
    expect(result.current.getSeverityColorByComment("above average")).toBe(theme.colors.g700);
    expect(result.current.getSeverityColorByComment("excellent")).toBe(theme.colors.g700);
    expect(result.current.getSeverityColorByComment("competitive")).toBe(theme.colors.g400);
    expect(result.current.getSeverityColorByComment("nonsense")).toBe(theme.colors.tk150);
    expect(result.current.getSeverityColorByComment(undefined)).toBe(theme.colors.tk150);
  });

  it("returns correct defcon color", () => {
    expect(result.current.getDefconColor(1)).toBe(theme.colors.r700);
    expect(result.current.getDefconColor(2)).toBe(theme.colors.r400);
    expect(result.current.getDefconColor(3)).toBe(theme.colors.y300);
    expect(result.current.getDefconColor(4)).toBe(theme.colors.g400);
    expect(result.current.getDefconColor(5)).toBe(theme.colors.g700);
    expect(result.current.getDefconColor(undefined)).toBe(theme.colors.tk150);
  });

  it("returns correct severity label", () => {
    expect(result.current.getSeverityLabelByLevel(1)).toBe("Very Bad");
    expect(result.current.getSeverityLabelByLevel(2)).toBe("Below Average");
    expect(result.current.getSeverityLabelByLevel(3)).toBe("Average");
    expect(result.current.getSeverityLabelByLevel(4)).toBe("Good");
    expect(result.current.getSeverityLabelByLevel(5)).toBe("Excellent");
    expect(result.current.getSeverityLabelByLevel(null)).toBe("Unknown");
  });
});
