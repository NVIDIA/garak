import { describe, it, expect } from "vitest";
import { useTooltipFormatter } from "../useTooltipFormatter";

describe("useTooltipFormatter", () => {
  it("formats full data", () => {
    const format = useTooltipFormatter();
    const output = format({
      detectorType: "Category A",
      data: {
        detector_score: 99.1234,
        zscore: 2.0,
        comment: "Looks good",
        itemStyle: { color: "#123456" },
      },
    });

    expect(output).toContain("Score: 99.12%");
    expect(output).toContain("Z-score:");
    expect(output).toContain('Comment: <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: #123456; margin-right: 6px; vertical-align: middle;"></span>Looks good');
  });

  it("handles missing values", () => {
    const format = useTooltipFormatter();
    const output = format({
      detectorType: "Other",
      data: {},
    });

    expect(output).toContain("Score: —");
    expect(output).toContain("Z-score:");
    expect(output).toContain('Comment: <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: #666; margin-right: 6px; vertical-align: middle;"></span>Unavailable');
  });

  it("includes DEFCON information when detector_defcon is available", () => {
    const format = useTooltipFormatter();
    const output = format({
      detectorType: "Security Detector",
      data: {
        detector_score: 85.5,
        zscore: 1.2,
        comment: "Above average",
        detector_defcon: 2,
        itemStyle: { color: "#ff6b6b" },
      },
    });

    expect(output).toContain("DEFCON: <strong>DC-2</strong>");
    expect(output).toContain("Score: 85.50%");
    expect(output).toContain("Z-score:");
  });

  it("excludes DEFCON when detector_defcon is not available", () => {
    const format = useTooltipFormatter();
    const output = format({
      detectorType: "Basic Detector",
      data: {
        detector_score: 75.0,
        zscore: 0.5,
        comment: "Average",
        itemStyle: { color: "#4ecdc4" },
      },
    });

    expect(output).not.toContain("DEFCON:");
    expect(output).toContain("Score: 75.00%");
  });

  it("includes attempt and hit counts when available", () => {
    const format = useTooltipFormatter();
    const output = format({
      detectorType: "Counter Detector",
      data: {
        detector_score: 90.0,
        zscore: 1.5,
        comment: "Good",
        detector_defcon: 1,
        attempt_count: 100,
        hit_count: 15,
        itemStyle: { color: "#red" },
      },
    });

    expect(output).toContain("DEFCON: <strong>DC-1</strong>");
    expect(output).toContain("Attempts: 100, Detected: 15");
  });
});
