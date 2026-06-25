/**
 * @file TaxonomyCellChart.test.tsx
 * @description Tests the click-to-select handling for the taxonomy cell bar
 *              chart, covering both bar (dataIndex) and axis-label (yAxis) clicks.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { render } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import TaxonomyCellChart from "../TaxonomyCellChart";
import type { AxisCell } from "../../../utils/techniqueIntentRollup";

interface ClickParams {
  componentType?: string;
  dataIndex?: number;
  value?: unknown;
}
interface CapturedProps {
  option: { series: { data: unknown[] }[] };
  style: { height: number; width: string };
  onEvents: { click: (params: ClickParams) => void };
}

let captured: CapturedProps;
vi.mock("echarts-for-react", () => ({
  __esModule: true,
  default: (props: CapturedProps) => {
    captured = props;
    return <div data-testid="echarts" />;
  },
}));

const cellOf = (otherKey: string, score: number): AxisCell => ({
  otherKey,
  otherLabel: `label-${otherKey}`,
  cell: {
    row: "tech",
    col: otherKey,
    score,
    nEvaluations: 100,
    passed: Math.round(score * 100),
    nones: 0,
    nDetectors: 1,
    leafCount: 1,
    leaves: [],
  },
});

const cells = [cellOf("a", 0.1), cellOf("b", 0.9)];

describe("TaxonomyCellChart", () => {
  beforeEach(() => {
    captured = undefined as unknown as CapturedProps;
  });

  it("sizes the chart from the options hook and plots a bar per cell", () => {
    render(<TaxonomyCellChart cells={cells} selectedKey={null} onSelect={vi.fn()} />);
    expect(captured.style.height, "height comes from the options hook").toBeGreaterThan(0);
    expect(captured.option.series[0].data, "one bar per cell").toHaveLength(cells.length);
  });

  it("selects a cell when its bar is clicked", () => {
    const onSelect = vi.fn();
    render(<TaxonomyCellChart cells={cells} selectedKey={null} onSelect={onSelect} />);
    captured.onEvents.click({ componentType: "series", dataIndex: 1 });
    expect(onSelect, "bar click resolves via dataIndex").toHaveBeenCalledWith("b");
  });

  it("toggles a cell off when its already-selected bar is clicked again", () => {
    const onSelect = vi.fn();
    render(<TaxonomyCellChart cells={cells} selectedKey="a" onSelect={onSelect} />);
    captured.onEvents.click({ componentType: "series", dataIndex: 0 });
    expect(onSelect, "re-clicking the selected bar clears it").toHaveBeenCalledWith(null);
  });

  it("selects via an axis-label click, matching the cell by its label", () => {
    const onSelect = vi.fn();
    render(<TaxonomyCellChart cells={cells} selectedKey={null} onSelect={onSelect} />);
    captured.onEvents.click({ componentType: "yAxis", value: "label-b" });
    expect(onSelect, "yAxis click resolves via the label value").toHaveBeenCalledWith("b");
  });

  it("ignores clicks that resolve to no cell", () => {
    const onSelect = vi.fn();
    render(<TaxonomyCellChart cells={cells} selectedKey={null} onSelect={onSelect} />);
    captured.onEvents.click({ componentType: "yAxis", value: "does-not-exist" });
    expect(onSelect, "an unmatched label is a no-op").not.toHaveBeenCalled();
  });
});
