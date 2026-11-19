/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { MatrixView } from "./techniqueIntentRollup";
import type { HeatmapSelection } from "../types/TechniqueIntentHeatmap";
import type { HeatmapLayout } from "./techniqueIntentHeatmapLayout";
import { color } from "echarts";

/** Chooses black or white text for contrast against a resolved KUI colour. */
export const contrastText = (colour: string): string => {
  const channels = color.parse(colour);
  if (!channels) return "#ffffff";
  const [r, g, b] = channels.slice(0, 3).map(channel => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.179 ? "#000000" : "#ffffff";
};

/** A graphic owned by ECharts, above tiles and independent of per-cell borders. */
export function heatmapOutline(
  id: string,
  selection: HeatmapSelection | null | undefined,
  view: MatrixView,
  layout: HeatmapLayout,
  stroke: string,
  dashed = false
) {
  const { firstCol, colCount, columnWidth, rowHeight, left, top } = layout;
  const row =
    selection?.axis === "intent"
      ? 0
      : view.rows.indexOf(
          selection?.axis === "cell" ? selection.technique : (selection?.key ?? "")
        );
  const col =
    selection?.axis === "technique"
      ? firstCol
      : view.cols.indexOf(selection?.axis === "cell" ? selection.intent : (selection?.key ?? ""));
  return {
    id,
    type: "rect",
    silent: true,
    z: dashed ? 90 : 100,
    ignore: !selection || row < 0 || col < firstCol || col >= firstCol + colCount,
    shape: {
      x: left + (col - firstCol) * columnWidth,
      y: top + row * rowHeight,
      width: selection?.axis === "technique" ? colCount * columnWidth : columnWidth,
      height: selection?.axis === "intent" ? view.rows.length * rowHeight : rowHeight,
    },
    style: { fill: "transparent", stroke, lineWidth: 2, lineDash: dashed ? [3, 3] : undefined },
  };
}
