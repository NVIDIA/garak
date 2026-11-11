/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { option, focusMatrix as matrix, dispatch } from "./heatmapFixtures";
import { render, screen, within } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import TechniqueIntentPanel from "../TechniqueIntentPanel";
describe("TechniqueIntentPanel", () => {
  it("shows an empty state for reports without taxonomy data", () => {
    render(<TechniqueIntentPanel />);
    expect(
      screen.getByText("No technique/intent data in this report"),
      "older reports retain their empty state"
    ).toBeVisible();
  });

  it("uses a single heatmap and inline details without duplicate taxonomy lists", () => {
    render(<TechniqueIntentPanel techniqueIntent={matrix} />);
    expect(
      screen.getByRole("grid", { name: "Technique by intent pass rates" }),
      "the matrix is the main view"
    ).toBeVisible();
    expect(screen.queryByText("By technique"), "the technique list is removed").toBeNull();
    expect(screen.queryByText("By intent"), "the intent list is removed").toBeNull();
    dispatch("click", { componentType: "yAxis", value: "t1" });
    expect(
      screen.getByText("Pass rate by intent. Click a bar for the pass/fail breakdown."),
      "row breakdown remains available"
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Open in list" }),
      "there is no redundant navigation action"
    ).toBeNull();
  });

  it("opens pairing details directly after the matrix without a recommendations banner", () => {
    render(<TechniqueIntentPanel techniqueIntent={matrix} />);
    expect(
      screen.queryByText("Notable pairings"),
      "no heuristic recommendations interrupt exploration"
    ).toBeNull();
    const pairing = {
      componentType: "series",
      data: { rowKey: "t1", colKey: "i1", value: [0, 0, 0] },
    };
    dispatch("click", pairing);
    expect(screen.getByText("Passed"), "pairing counts still open inline").toBeVisible();
    expect(option.graphic.elements[0].ignore, "the selected cell remains outlined").toBe(false);
    dispatch("click", pairing);
    expect(
      screen.queryByRole("button", { name: "Clear selection" }),
      "direct cell selection still toggles off"
    ).toBeNull();
  });

  it("shows one numeric legend and retains risk-first ordering without focus controls", () => {
    render(<TechniqueIntentPanel techniqueIntent={matrix} />);
    const legend = within(screen.getByRole("group", { name: "Pass rate legend" }));
    expect(legend.getByText("0%"), "the legend shows the lowest pass rate").toBeVisible();
    expect(legend.getByText("100%"), "the legend shows the highest pass rate").toBeVisible();
    expect(legend.getByText("Not evaluated"), "missing data has a separate key").toBeVisible();
    expect(
      legend.getByText("Lower means more failures"),
      "score direction is explicit"
    ).toBeVisible();
    expect(screen.getAllByText("Pass rate"), "the metric is explained once").toHaveLength(1);
    expect(
      screen.queryByRole("button", { name: /^DC-/ }),
      "risk focus has been removed"
    ).toBeNull();
    expect(option.yAxis.data, "the matrix retains its default risk-first order").toEqual([
      "t1",
      "t2",
    ]);
    const colours = option.series[0].data.map(point => point.itemStyle.color);
    dispatch("click", {
      componentType: "series",
      data: { rowKey: "t1", colKey: "i1", value: [0, 0, 0] },
    });
    expect(
      option.series[0].data.map(point => point.itemStyle.color),
      "selection preserves score colours"
    ).toEqual(colours);
    expect(screen.getByText("DC-1"), "DEFCON remains available in details").toBeVisible();
  });
});
