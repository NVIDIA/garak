/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { view, dispatch } from "./heatmapFixtures";
import TestHeatmap from "./HeatmapHarness";
import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import type { HeatmapEvent } from "../../../types/TechniqueIntentHeatmap";
import { buildMatrixView } from "../../../utils/techniqueIntentRollup";
const targets: HeatmapEvent[] = [
  { componentType: "series", data: { rowKey: "t1", colKey: "i1", value: [0, 0, 0] } },
  { componentType: "yAxis", value: "t1" },
  { componentType: "xAxis", value: "i1" },
];
describe("heatmap selection", () => {
  it.each(targets)("shows probe provenance from $componentType details", event => {
    const modern = buildMatrixView({
      t1: {
        i1: {
          score: 0.5,
          passed: 1,
          total_evaluated: 2,
          nones: 0,
          probe_detector_pairs: [
            ["grandma.Win10", "always.Fail"],
            ["grandma.Win10", "always.Pass"],
          ],
        },
      },
    });
    const open = vi.fn();
    render(<TestHeatmap view={modern} onProbeSelect={open} />);
    dispatch("click", event);
    expect(
      screen.getByRole("button", { name: "Open grandma.Win10 in report" }),
      "pairing references are reachable from both axes and cells"
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Open grandma.Win10 in report" }));
    expect(open, "all detail paths navigate to the contributing probe").toHaveBeenCalledWith(
      "grandma.Win10"
    );
    expect(
      screen.getByText("Counts are detector evaluations, pooled across 2 detectors."),
      "new digests derive the count from provenance"
    ).toBeVisible();
  });
  it.each(targets)("toggles the selected $componentType", event => {
    render(<TestHeatmap view={view} />);
    dispatch("click", event);
    expect(
      screen.getByRole("button", { name: "Clear selection" }),
      "first click reveals details"
    ).toBeVisible();
    dispatch("click", event);
    expect(
      screen.queryByRole("button", { name: "Clear selection" }),
      "second click clears details"
    ).toBeNull();
    expect(screen.getByRole("grid"), "the matrix stays mounted").toBeVisible();
  });
  it("uses raw keys even when display labels match", () => {
    const select = vi.fn();
    render(<TestHeatmap view={view} onSelect={select} />);
    dispatch("click", { componentType: "yAxis", value: "t2" });
    expect(select, "labels do not identify selection").toHaveBeenLastCalledWith({
      axis: "technique",
      key: "t2",
    });
    dispatch("click", { componentType: "yAxis", value: "t1" });
    expect(select, "another key switches rather than clears").toHaveBeenLastCalledWith({
      axis: "technique",
      key: "t1",
    });
  });
  it("ignores missing pairings and unrelated events", () => {
    const select = vi.fn();
    render(<TestHeatmap view={view} onSelect={select} />);
    dispatch("click", {
      componentType: "series",
      data: { rowKey: "t1", colKey: "i2", value: [1, 0, -1] },
    });
    dispatch("click", { componentType: "xAxis", value: "missing" });
    dispatch("click", { componentType: "legend" });
    expect(select, "missing results do not select another cell").not.toHaveBeenCalled();
  });
  it("clears a measured zero result without losing the chart", () => {
    render(<TestHeatmap view={view} />);
    dispatch("click", targets[0]);
    expect(screen.getByText("Passed"), "zero has real counts").toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Clear selection" }));
    expect(screen.queryByText("Passed"), "the detail is dismissed").toBeNull();
    expect(screen.getByRole("grid")).toBeVisible();
  });
});
