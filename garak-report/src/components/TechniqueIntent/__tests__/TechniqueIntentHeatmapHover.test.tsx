/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { view, dispatch, chart, events, option } from "./heatmapFixtures";
import TestHeatmap from "./HeatmapHarness";
import { act, render, screen, within } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
describe("heatmap axis hover", () => {
  it("keeps chart bindings intact while React updates tooltip content", () => {
    render(<TestHeatmap view={view} />);
    const bindings = events;
    const update = vi.fn();
    act(() => {
      option.tooltip.formatter(
        { data: { value: [0, 0, 0], rowKey: "t1", colKey: "i1" } },
        "preview",
        update
      );
    });
    expect(update, "ECharts receives the committed tooltip content").toHaveBeenCalledOnce();
    expect(
      within(update.mock.calls[0][1]).getByRole("tooltip", { name: "Pairing preview" })
    ).toBeDefined();
    expect(events, "preview content updates do not rebind ECharts events").toBe(bindings);
    dispatch("click", { componentType: "yAxis", value: "t1" });
    dispatch("click", { componentType: "yAxis", value: "t1" });
    expect(
      screen.queryByRole("button", { name: "Clear selection" }),
      "the current selection still toggles after tooltip updates"
    ).not.toBeInTheDocument();
  });
  it.each([
    ["xAxis", "i2"],
    ["yAxis", "t2"],
  ])("highlights %s through ECharts-owned graphics", (componentType, value) => {
    chart.setOption.mockClear();
    render(<TestHeatmap view={view} />);
    dispatch("click", { componentType: "yAxis", value: "t1" });
    dispatch("mouseover", { componentType, value });
    const graphic =
      chart.setOption.mock.calls[chart.setOption.mock.calls.length - 1][0].graphic.elements[0];
    expect(graphic.id).toBe("technique-intent-hover");
    expect(graphic.silent, "hover cannot intercept activation").toBe(true);
    expect(graphic.z, "hover stays below persistent selection").toBe(10);
    expect(graphic.shape.width).toBe(componentType === "xAxis" ? 452 : 904);
    expect(graphic.shape.height).toBe(componentType === "yAxis" ? 44 : 88);
    dispatch("mouseout", {});
    expect(chart.setOption).toHaveBeenLastCalledWith({
      graphic: { elements: [{ id: "technique-intent-hover", ignore: true }] },
    });
    expect(
      screen.getByRole("button", { name: "Clear selection" }),
      "hover does not clear the selected axis"
    ).toBeVisible();
  });
});
