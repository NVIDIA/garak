/**
 * @file useTaxonomyCellChartOptions.ts
 * @description Hook to build ECharts options for the taxonomy cell bar chart
 *              (a primary entry's worst-first cross-axis pass rates).
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import useSeverityColor from "./useSeverityColor";
import { scoreToDefcon, THEME_COLORS, CHART_OPACITY } from "../constants";
import { formatRate } from "../utils/formatPercentage";
import type { AxisCell } from "../utils/techniqueIntentRollup";

/** Pixels of vertical space per bar, used to size the chart to its data. */
const ROW_PX = 30;

/**
 * Builds ECharts options for the horizontal, DEFCON-coloured cell bar chart and
 * the height it needs. Non-selected bars dim when a selection is active, the
 * same focus treatment the probe and detector charts use.
 *
 * @param cells - Worst-first cross-axis cells to plot
 * @param selectedKey - Currently selected cell key, or null
 * @param isDark - Whether dark theme is active
 * @returns The ECharts `option` and the chart's pixel `height`
 */
export function useTaxonomyCellChartOptions(
  cells: AxisCell[],
  selectedKey: string | null,
  isDark?: boolean,
) {
  const { getSeverityColorByLevel } = useSeverityColor();
  const textColor = isDark ? THEME_COLORS.text.dark : THEME_COLORS.text.light;
  const splitLineColor = isDark ? THEME_COLORS.chart.splitLine.dark : THEME_COLORS.chart.splitLine.light;

  const option = useMemo(
    () => ({
      grid: { left: 8, right: 56, top: 8, bottom: 8, containLabel: true },
      tooltip: {
        trigger: "item",
        confine: true,
        formatter: (params: { dataIndex: number } | { dataIndex: number }[]) => {
          const p = Array.isArray(params) ? params[0] : params;
          const cell = cells[p.dataIndex];
          if (!cell) return "";
          return `${cell.otherLabel}<br/>${formatRate(cell.cell.score)} · ${cell.cell.nEvaluations.toLocaleString()} evals`;
        },
      },
      xAxis: {
        type: "value",
        min: 0,
        max: 100,
        axisLabel: { formatter: "{value}%", color: textColor },
        splitLine: { lineStyle: { color: splitLineColor } },
      },
      yAxis: {
        type: "category",
        inverse: true, // worst (index 0) on top
        data: cells.map(c => c.otherLabel),
        axisTick: { show: false },
        // triggerEvent (on the axis, not the label) makes label clicks fire, so a
        // label click can select the row just like clicking its bar.
        triggerEvent: true,
        axisLabel: { color: textColor },
      },
      series: [
        {
          type: "bar",
          barMaxWidth: 22,
          data: cells.map(c => {
            const dimmed = !!selectedKey && selectedKey !== c.otherKey;
            return {
              value: Math.round(c.cell.score * 100),
              itemStyle: {
                color: getSeverityColorByLevel(scoreToDefcon(c.cell.score)),
                opacity: dimmed ? CHART_OPACITY.dimmed : CHART_OPACITY.full,
                borderRadius: 2,
              },
            };
          }),
          label: { show: true, position: "right", formatter: "{c}%", color: textColor, fontWeight: 600 },
        },
      ],
    }),
    [cells, selectedKey, getSeverityColorByLevel, textColor, splitLineColor],
  );

  const height = Math.max(120, cells.length * ROW_PX + 32);

  return { option, height };
}
