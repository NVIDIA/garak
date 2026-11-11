/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Compose the matrix's independently memoised data, layout and ECharts options. */
import { useMemo } from "react";
import { HEATMAP_MIN_EVALUATIONS } from "../constants";
import type { MatrixView } from "../utils/techniqueIntentRollup";
import type { HeatmapSelection, HeatmapWindow } from "../types/TechniqueIntentHeatmap";
import { getHeatmapLayout } from "../utils/techniqueIntentHeatmapLayout";
import { heatmapOutline } from "../utils/techniqueIntentHeatmapGraphics";
import { heatmapAxes, heatmapVisualMap } from "../utils/techniqueIntentHeatmapAxes";
import { heatmapTooltipPosition } from "../utils/techniqueIntentHeatmapTooltipPosition";
import { useTechniqueIntentHeatmapData } from "./useTechniqueIntentHeatmapData";
import { useTechniqueIntentHeatmapTooltip } from "./useTechniqueIntentHeatmapTooltip";

interface Options extends HeatmapWindow {
  selection?: HeatmapSelection | null;
  focus?: HeatmapSelection | null;
  width?: number;
  minEvaluations?: number;
}
export function useTechniqueIntentHeatmapOptions(
  view: MatrixView,
  isDark?: boolean,
  {
    selection,
    focus,
    width = 1200,
    colSpan,
    colStart = 0,
    minEvaluations = HEATMAP_MIN_EVALUATIONS,
  }: Options = {}
) {
  const layout = useMemo(
    () => getHeatmapLayout(view, width, { colSpan, colStart }),
    [view, width, colSpan, colStart]
  );
  const { data, groups, palette } = useTechniqueIntentHeatmapData(
    view,
    layout,
    isDark,
    selection,
    minEvaluations
  );
  const { formatters, portal } = useTechniqueIntentHeatmapTooltip(view, groups, minEvaluations);
  const option = useMemo(
    () => ({
      animation: false,
      aria: { enabled: false },
      graphic: {
        elements: [
          heatmapOutline("technique-intent-selection", selection, view, layout, palette.text),
          heatmapOutline("technique-intent-focus", focus, view, layout, palette.text, true),
          {
            id: "technique-intent-hover",
            type: "rect",
            silent: true,
            z: 10,
            ignore: true,
            shape: { x: 0, y: 0, width: 0, height: 0 },
            style: { fill: palette.hover },
          },
        ],
      },
      grid: { left: layout.left, right: layout.right, top: layout.top, bottom: layout.bottom },
      visualMap: heatmapVisualMap(palette.colours),
      ...heatmapAxes(view, layout, palette, formatters),
      tooltip: {
        trigger: "item",
        confine: false,
        transitionDuration: 0,
        hideDelay: 80,
        enterable: false,
        padding: 16,
        backgroundColor: "var(--background-color-surface-overlay)",
        borderColor: "var(--border-color-base)",
        borderWidth: 1,
        textStyle: { color: palette.text },
        extraCssText:
          "width: min(320px, calc(100vw - 64px)); box-sizing: border-box; white-space: normal; overflow-wrap: anywhere; border-radius: var(--radius-md); box-shadow: var(--shadow-md); pointer-events: none;",
        position: heatmapTooltipPosition(layout),
        formatter: formatters.cell,
      },
      series: [{ type: "heatmap", data, emphasis: { disabled: true } }],
    }),
    [view, layout, palette, data, selection, focus, formatters]
  );
  return {
    option,
    ...layout,
    layout,
    groups,
    minEvaluations,
    hoverColour: palette.hover,
    tooltipPortal: portal,
  };
}
