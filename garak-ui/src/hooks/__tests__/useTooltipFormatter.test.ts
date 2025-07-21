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
    expect(output).toContain('Comment: <span style="color:#123456">Looks good</span>');
  });

  it("handles missing values", () => {
    const format = useTooltipFormatter();
    const output = format({
      detectorType: "Other",
      data: {},
    });

    expect(output).toContain("Score: —");
    expect(output).toContain("Z-score:");
    expect(output).toContain('Comment: <span style="color:#666">Unavailable</span>');
  });
});
