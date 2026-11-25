/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { renderHook } from "@testing-library/react";
import { graphic, init } from "echarts";
import { describe, expect, it } from "vitest";
import { counts } from "../../hooks/__tests__/heatmapFixtures";
import { useTechniqueIntentHeatmapOptions } from "../../hooks/useTechniqueIntentHeatmapOptions";
import { buildMatrixView } from "../techniqueIntentRollup";

describe("heatmap label layout", () => {
  it.each([
    [390, 20, 20],
    [900, 20, 20],
    [1600, 20, 20],
    [2560, 52, 52],
    [390, 52, 52],
    [1440, 20, 4],
  ])("keeps headings above cells at width=%s, intents=%s, visible=%s", (width, count, colSpan) => {
    const view = buildMatrixView({
      t: Object.fromEntries(
        Array.from({ length: count }, (_, index) => [
          `I${index}`,
          {
            ...counts(0.5),
            name:
              index === 0 ? "Produce degraded or unstable output when triggered" : "Intent name",
          },
        ])
      ),
    });
    const { result } = renderHook(() =>
      useTechniqueIntentHeatmapOptions(view, true, { width, colSpan })
    );
    const model = result.current;
    const chart = init(null, undefined, {
      renderer: "svg",
      ssr: true,
      width,
      height: model.height,
    });
    try {
      chart.setOption(model.option);
      chart.renderToSVGString();
      const labels: graphic.Text[] = [];
      const names = new Set(view.cols.map(view.colName));
      chart.getZr().storage.traverse(element => {
        if (element instanceof graphic.Text && names.has(element.style.text ?? ""))
          labels.push(element);
      });
      expect(labels.length, "visible intents have headings").toBeGreaterThan(0);
      for (const label of labels) {
        const box = label.getBoundingRect().clone();
        const transform = label.getComputedTransform();
        if (transform) box.applyTransform(transform);
        expect(
          box.y + box.height,
          "the complete label clears the first cell row"
        ).toBeLessThanOrEqual(model.top - 8);
        expect(box.y, "headings fit inside the reserved top space").toBeGreaterThanOrEqual(0);
        expect(box.x, "the first heading stays inside the chart").toBeGreaterThanOrEqual(0);
        expect(box.x + box.width, "the last heading stays inside the chart").toBeLessThanOrEqual(
          width
        );
      }
    } finally {
      chart.dispose();
    }
  });

  it("preserves literal rich-text syntax in a custom taxonomy", () => {
    const name = "Return {code|verbatim} credentials";
    const key = "{custom|intent}";
    const view = buildMatrixView({ t: { [key]: { ...counts(0.5), name } } });
    const { result } = renderHook(() => useTechniqueIntentHeatmapOptions(view));
    const labels = result.current.option.xAxis.axisLabel;
    expect(labels.formatter(key), "the full custom name remains literal").toBe(name);
    expect(result.current.option.xAxis.data, "events retain the custom code").toEqual([key]);
  });
});
