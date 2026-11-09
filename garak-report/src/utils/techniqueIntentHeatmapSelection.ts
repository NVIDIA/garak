/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { MatrixView } from "./techniqueIntentRollup";
import type {
  HeatmapCell,
  HeatmapCursor,
  HeatmapEvent,
  HeatmapSelection,
} from "../types/TechniqueIntentHeatmap";

export function sameHeatmapSelection(
  a: HeatmapSelection | null | undefined,
  b: HeatmapSelection | null | undefined
) {
  if (!a || !b) return a === b;
  return (
    a.axis === b.axis &&
    (a.axis === "cell" && b.axis === "cell"
      ? a.technique === b.technique && a.intent === b.intent
      : a.axis !== "cell" && b.axis !== "cell" && a.key === b.key)
  );
}
export function heatmapEventSelection(
  params: HeatmapEvent,
  view: MatrixView
): HeatmapSelection | undefined {
  const key = String(params.value);
  if (params.componentType === "xAxis" && view.cols.includes(key)) return { axis: "intent", key };
  if (params.componentType === "yAxis" && view.rows.includes(key))
    return { axis: "technique", key };
  const point = params.data as HeatmapCell | undefined;
  if (params.componentType === "series" && point && view.cell(point.rowKey, point.colKey))
    return { axis: "cell", technique: point.rowKey, intent: point.colKey };
}
export function cursorSelection({ row, col }: HeatmapCursor, view: MatrixView): HeatmapSelection {
  if (row < 0) return { axis: "intent", key: view.cols[col] };
  if (col < 0) return { axis: "technique", key: view.rows[row] };
  return { axis: "cell", technique: view.rows[row], intent: view.cols[col] };
}
