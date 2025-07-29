import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import DetectorsView from "../DetectorsView";
import { describe, it, expect, vi } from "vitest";

// Mock hooks
vi.mock("../../hooks/useGroupedDetectors", () => ({
  useGroupedDetectors: () => ({
    Cat: [
      { label: "A", zscore: null, detector_score: null, color: "#ccc", comment: "Unavailable" },
    ],
  }),
}));
vi.mock("../../hooks/useSortedDetectors", () => ({ useSortedDetectors: () => (e: any) => e }));
vi.mock("../../hooks/useDetectorsChartSeries", () => ({ useDetectorsChartSeries: () => () => ({ pointSeries:{}, lineSeries:{}, naSeries:{}, visible:[] })}));
vi.mock("../../hooks/useTooltipFormatter", () => ({ useTooltipFormatter: () => () => "" }));
vi.mock("echarts-for-react", () => ({ __esModule:true, default: () => <div /> }));

const probe = { probe_name: "probe", detectors:[{detector_name:"x"}] } as any;

describe("DetectorsView N/A", () => {
  it("shows unavailable message when all detectors filtered", () => {
    render(<DetectorsView probe={probe} allProbes={[probe]} setSelectedProbe={()=>{}} />);
    expect(screen.getByText(/All entries are unavailable/)).toBeInTheDocument();
  });
}); 