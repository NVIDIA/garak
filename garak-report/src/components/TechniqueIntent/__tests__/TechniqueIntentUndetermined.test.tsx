/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { dispatch } from "./heatmapFixtures";
import { fireEvent, render, screen } from "@testing-library/react";
import { renderHook } from "@testing-library/react";
import { init } from "echarts";
import { describe, expect, it, vi } from "vitest";
import TechniqueIntentPanel from "../TechniqueIntentPanel";
import TechniqueIntentTooltip from "../TechniqueIntentTooltip";
import { buildMatrixView } from "../../../utils/techniqueIntentRollup";
import { useTechniqueIntentHeatmapOptions } from "../../../hooks/useTechniqueIntentHeatmapOptions";
import type { TechniqueIntentMatrix } from "../../../types/ReportEntry";

const unknown = {
  name: "Execute a file",
  score: null,
  passed: 0,
  total_evaluated: 0,
  nones: 210,
  probe_detector_pairs: [["probe.Check", "detector.Check"]] as [string, string][],
};
const matrix: TechniqueIntentMatrix = { a: { X: unknown }, b: { X: unknown } };
const view = buildMatrixView(matrix);

describe("undetermined technique/intent results", () => {
  it("explains missing verdicts without assigning a pass rate or risk", () => {
    render(<TechniqueIntentTooltip view={view} technique="a" intent="X" />);
    expect(screen.getByText("Undetermined"), "no verdict differs from no results").toBeVisible();
    expect(
      screen.getByText(/210 detector results had no verdict/),
      "processed results remain accounted for"
    ).toBeVisible();
    expect(
      screen.queryByText(/DC-/),
      "undetermined results have no risk classification"
    ).toBeNull();
    expect(
      screen.queryByText("Low evaluation count"),
      "unscored results do not get a low-score-count badge"
    ).toBeNull();
  });

  it("keeps undetermined axis entries selectable and opens their contributing probe", () => {
    const open = vi.fn();
    render(<TechniqueIntentPanel techniqueIntent={matrix} onProbeSelect={open} />);
    dispatch("click", { componentType: "xAxis", value: "X" });
    fireEvent.click(screen.getByRole("button", { name: "a" }));
    expect(
      screen.getByText("Unavailable"),
      "details do not manufacture a zero pass rate"
    ).toBeVisible();
    expect(screen.getByText("210"), "details retain all undetermined results").toBeVisible();
    expect(
      screen.queryByText("No failures recorded"),
      "no verdicts are not an all-pass result"
    ).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Open probe.Check in report" }));
    expect(open, "provenance navigation remains available without verdicts").toHaveBeenCalledWith(
      "probe.Check"
    );
  });

  it.each([false, true])("renders a neutral undetermined tile in dark=%s", isDark => {
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view, isDark));
    const data = result.current.option.series[0].data;
    expect(data[0].label.formatter, "undetermined tiles are labelled without a percentage").toBe(
      "Undetermined"
    );
    expect(
      data[0].itemStyle.decal,
      "undetermined is distinct from the low-count pattern"
    ).toBeUndefined();
    const chart = init(null, undefined, {
      renderer: "svg",
      ssr: true,
      width: 1200,
      height: result.current.height,
    });
    try {
      chart.setOption(result.current.option);
      expect(chart.renderToSVGString(), "the real renderer retains undetermined cells").toContain(
        "Undetermined"
      );
      expect(
        chart.renderToSVGString(),
        "missing verdicts are never shown as measured failures"
      ).not.toContain("0%");
    } finally {
      chart.dispose();
    }
  });
});
