/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { view, counts } from "./heatmapFixtures";
import { render, screen, act } from "@testing-library/react";
import { describe, it, expect, vi, afterEach } from "vitest";
import { useTechniqueIntentHeatmapOptions } from "../useTechniqueIntentHeatmapOptions";
import { buildMatrixView } from "../../utils/techniqueIntentRollup";
import type { MatrixView } from "../../utils/techniqueIntentRollup";
let model: ReturnType<typeof useTechniqueIntentHeatmapOptions>;
const attached: HTMLElement[] = [];
const callback = vi.fn((_: string, content: string | HTMLElement) => {
  if (typeof content !== "string") {
    document.body.append(content);
    attached.push(content);
  }
});
const Preview = ({ view }: { view: MatrixView }) => {
  model = useTechniqueIntentHeatmapOptions(view, false, { colSpan: 1 });
  return model.tooltipPortal;
};
afterEach(() => {
  for (const host of attached) host.remove();
  attached.length = 0;
  callback.mockClear();
});
describe("heatmap client previews", () => {
  it("renders escaped taxonomy content and actual counts through React", () => {
    const custom = buildMatrixView(
      { t: { _summary: { name: "<img src=x>", n_intents: 1, n_detectors: 1 }, i1: counts(0.4) } },
      { i1: { name: "<svg onload=bad>", descr: "<script>bad</script>" } }
    );
    render(<Preview view={custom} />);
    act(() =>
      model.option.tooltip.formatter({ data: model.option.series[0].data[0] }, "cell", callback)
    );
    expect(screen.getByRole("tooltip")).toHaveTextContent("40 of 100 detector evaluations passed");
    expect(screen.getByText("<img src=x>")).toBeVisible();
    expect(screen.getByText("i1 - <svg onload=bad>")).toBeVisible();
    expect(
      attached[0].querySelector("script,img,svg"),
      "taxonomy text never becomes markup"
    ).toBeNull();
  });
  it.each(["xAxis", "yAxis"] as const)("previews %s from the complete report", axis => {
    render(<Preview view={view} />);
    act(() =>
      model.option[axis].tooltip.formatter(
        { value: axis === "xAxis" ? "i1" : "demon:one" },
        "axis",
        callback
      )
    );
    expect(screen.getByRole("group", { name: "Weakest pairing" })).toHaveTextContent("0%");
    expect(screen.getByRole("group", { name: "Across tested pairings" })).toHaveTextContent(
      "2 of 2"
    );
    expect(model.option[axis].tooltip.formatter({ value: "missing" }, "missing", callback)).toBe(
      ""
    );
  });
  it("reuses committed content and unmounts it with the chart", () => {
    const { unmount } = render(<Preview view={view} />);
    const point = { data: model.option.series[0].data[0] };
    act(() => model.option.tooltip.formatter(point, "first", callback));
    const host = attached[0];
    act(() => expect(model.option.tooltip.formatter(point, "repeat", callback)).toBe(host));
    expect(callback, "the second hover needs no new portal commit").toHaveBeenCalledOnce();
    unmount();
    expect(host, "portal content follows the React lifecycle").toBeEmptyDOMElement();
  });
  it("keeps the latest hover when returning to a cell before React commits", () => {
    render(<Preview view={view} />);
    const [first, second] = model.option.series[0].data;
    act(() => model.option.tooltip.formatter({ data: first }, "first", callback));
    const original = screen.getByRole("tooltip").textContent;
    act(() => {
      model.option.tooltip.formatter({ data: second }, "second", callback);
      model.option.tooltip.formatter({ data: first }, "return", callback);
    });
    expect(
      screen.getByRole("tooltip").textContent,
      "an intermediate hover cannot replace the current pairing"
    ).toBe(original);
  });
  it("delivers pending content using the latest ECharts ticket", () => {
    render(<Preview view={view} />);
    const point = { data: model.option.series[0].data[0] };
    act(() => {
      model.option.tooltip.formatter(point, "superseded", callback);
      model.option.tooltip.formatter(point, "latest", callback);
    });
    expect(callback, "pending hovers share one portal commit").toHaveBeenCalledOnce();
    expect(callback.mock.calls[0][0], "ECharts can accept the current request").toBe("latest");
  });
});
