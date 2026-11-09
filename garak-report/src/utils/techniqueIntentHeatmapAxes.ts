/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** ECharts axes, colour scale and horizontal navigation for the matrix. */
import type { MatrixView } from "./techniqueIntentRollup";
import type { TooltipFormatter } from "../types/TechniqueIntentHeatmap";
import type { HeatmapLayout } from "./techniqueIntentHeatmapLayout";
import type { HeatmapPalette } from "../hooks/useTechniqueIntentHeatmapData";

export function heatmapAxes(
  view: MatrixView,
  layout: HeatmapLayout,
  palette: HeatmapPalette,
  tooltips: { intent: TooltipFormatter; technique: TooltipFormatter }
) {
  const columnIndices = new Map(view.cols.map((key, index) => [key, index]));
  const axisPointer = {
    show: true,
    type: "shadow",
    triggerTooltip: false,
    triggerEmphasis: false,
    label: { show: false },
    shadowStyle: { color: palette.text, opacity: 0.07 },
  };
  return {
    xAxis: {
      type: "category",
      tooltip: { show: true, formatter: tooltips.intent },
      axisPointer,
      position: "top",
      data: view.cols,
      triggerEvent: true,
      axisTick: { show: false },
      axisLine: { show: false },
      axisLabel: {
        interval: layout.labelInterval,
        rotate: layout.labelAngle,
        align: layout.compactLabels && layout.labelAngle > 0 ? "right" : undefined,
        verticalAlign: layout.compactLabels && layout.labelAngle > 0 ? "middle" : undefined,
        fontSize: layout.labelFontSize,
        width: layout.compactLabels ? undefined : layout.labelWidth,
        lineHeight: layout.labelLineHeight,
        overflow: layout.compactLabels ? undefined : "break",
        color: (key: string) =>
          Math.floor((columnIndices.get(key) ?? -1) / (layout.labelInterval + 1)) % 2 === 0
            ? palette.text
            : palette.alternate,
        formatter: (key: string) =>
          layout.compactLabels ? key : view.colLabel(key).replace(" - ", "\n"),
      },
    },
    yAxis: {
      type: "category",
      tooltip: { show: true, formatter: tooltips.technique },
      axisPointer,
      inverse: true,
      data: view.rows,
      triggerEvent: true,
      axisTick: { show: false },
      axisLine: { show: false },
      axisLabel: {
        interval: 0,
        width: layout.left - 24,
        height: Math.min(40, layout.rowHeight - 4),
        lineHeight: 16,
        overflow: "break",
        lineOverflow: "truncate",
        color: palette.text,
        formatter: view.rowLabel,
      },
    },
    dataZoom: [
      {
        type: "slider",
        xAxisIndex: 0,
        show: view.cols.length > layout.colCount,
        startValue: layout.firstCol,
        endValue: layout.firstCol + layout.colCount - 1,
        zoomLock: false,
        brushSelect: false,
        showDetail: false,
        showDataShadow: false,
        bottom: 8,
        height: 20,
        borderColor: palette.border,
        textStyle: { color: palette.text },
      },
    ],
  };
}
export function heatmapVisualMap(colours: string[]) {
  return {
    show: false,
    type: "continuous",
    min: 0,
    max: 1,
    dimension: 2,
    inRange: { color: colours },
    outOfRange: { color: "transparent" },
  };
}
