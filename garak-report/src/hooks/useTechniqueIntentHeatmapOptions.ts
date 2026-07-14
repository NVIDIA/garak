/**
 * @file useTechniqueIntentHeatmapOptions.ts
 * @description Hook to build ECharts options for the technique x intent heatmap.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import type { TechniqueIntentMatrix } from "../types/ReportEntry";
import {
  THEME_COLORS,
  ABSOLUTE_DEFCON_BOUNDS,
  DEFCON_LABELS,
  DEFCON_PCT_RANGE,
  RISK_RAMP_COLORS,
} from "../constants";
import { formatPercentage } from "../utils/formatPercentage";
import { shortenTechnique, formatTechniqueFull } from "../utils/taxonomyLabels";

/** DEFCON bucket boundaries as pass-rate percentages (mirrors scoreToDefcon). */
const PCT_BOUNDS = {
  TERRIBLE: ABSOLUTE_DEFCON_BOUNDS.TERRIBLE * 100,
  BELOW_AVG: ABSOLUTE_DEFCON_BOUNDS.BELOW_AVG * 100,
  ABOVE_AVG: ABSOLUTE_DEFCON_BOUNDS.ABOVE_AVG * 100,
  EXCELLENT: ABSOLUTE_DEFCON_BOUNDS.EXCELLENT * 100,
};

export interface HeatmapCell {
  value: [number, number, number];
  techniqueFull: string;
  intentKey: string;
  score: number;
  nEvaluations: number;
  detectors: string[];
}

/**
 * Builds ECharts options for a technique (rows) x intent (columns) heatmap.
 * Cells are colored on a continuous 0-100% pass-rate scale.
 *
 * @param matrix - Nested technique -> intent -> score map
 * @param isDark - Whether dark theme is active
 * @returns ECharts option configuration object
 */
export function useTechniqueIntentHeatmapOptions(
  matrix: TechniqueIntentMatrix,
  isDark?: boolean,
) {
  const textColor = isDark ? THEME_COLORS.text.dark : THEME_COLORS.text.light;

  return useMemo(() => {
    // Monotonic risk ramp (DC-1..DC-5), ending on NVIDIA green.
    const rampColors = [1, 2, 3, 4, 5].map(
      d => RISK_RAMP_COLORS[d as 1 | 2 | 3 | 4 | 5],
    );
    const techniques = Object.keys(matrix).sort();

    const intentSet = new Set<string>();
    techniques.forEach(t => {
      Object.keys(matrix[t]).forEach(i => intentSet.add(i));
    });
    const intents = Array.from(intentSet).sort();

    const cells: HeatmapCell[] = [];
    techniques.forEach((technique, yIndex) => {
      intents.forEach((intent, xIndex) => {
        const entry = matrix[technique]?.[intent];
        if (!entry) return;
        cells.push({
          value: [xIndex, yIndex, Math.round(entry.score * 100 * 100) / 100],
          techniqueFull: formatTechniqueFull(technique),
          intentKey: intent,
          score: entry.score,
          nEvaluations: entry.n_evaluations,
          detectors: entry.detectors_used ?? [],
        });
      });
    });

    return {
      tooltip: {
        position: "top",
        confine: true,
        formatter: (params: { data: HeatmapCell }) => {
          const d = params.data;
          if (!d) return "";
          return (
            `<strong>${d.techniqueFull}</strong><br/>` +
            `<span style="opacity:0.75">Intent: ${d.intentKey}</span><br/>` +
            `Pass rate: ${formatPercentage(d.value[2])}<br/>` +
            `Evaluations: ${d.nEvaluations.toLocaleString()}<br/>` +
            `<span style="opacity:0.6">Click to drill down</span>`
          );
        },
      },
      grid: {
        containLabel: true,
        left: 10,
        right: 20,
        top: 10,
        bottom: 60,
      },
      xAxis: {
        type: "category",
        data: intents,
        splitArea: { show: true },
        axisLabel: {
          rotate: 45,
          interval: 0,
          fontSize: 12,
          color: textColor,
        },
        axisLine: { lineStyle: { color: textColor } },
      },
      yAxis: {
        type: "category",
        data: techniques.map(shortenTechnique),
        splitArea: { show: true },
        axisLabel: {
          interval: 0,
          fontSize: 12,
          color: textColor,
        },
        axisLine: { lineStyle: { color: textColor } },
      },
      visualMap: {
        type: "piecewise",
        min: 0,
        max: 100,
        orient: "horizontal",
        left: "center",
        bottom: 0,
        itemWidth: 14,
        itemHeight: 14,
        textStyle: { color: textColor, fontSize: 11 },
        // Buckets match scoreToDefcon; colors follow the monotonic risk ramp.
        // Labels pair the risk word with its pass-rate range so the legend,
        // the DEFCON header, and the cell percentages all read as one scale.
        pieces: [
          {
            gte: PCT_BOUNDS.EXCELLENT,
            label: `${DEFCON_LABELS[5]} (${DEFCON_PCT_RANGE[5]})`,
            color: rampColors[4],
          },
          {
            gte: PCT_BOUNDS.ABOVE_AVG,
            lt: PCT_BOUNDS.EXCELLENT,
            label: `${DEFCON_LABELS[4]} (${DEFCON_PCT_RANGE[4]})`,
            color: rampColors[3],
          },
          {
            gte: PCT_BOUNDS.BELOW_AVG,
            lt: PCT_BOUNDS.ABOVE_AVG,
            label: `${DEFCON_LABELS[3]} (${DEFCON_PCT_RANGE[3]})`,
            color: rampColors[2],
          },
          {
            gte: PCT_BOUNDS.TERRIBLE,
            lt: PCT_BOUNDS.BELOW_AVG,
            label: `${DEFCON_LABELS[2]} (${DEFCON_PCT_RANGE[2]})`,
            color: rampColors[1],
          },
          {
            lt: PCT_BOUNDS.TERRIBLE,
            label: `${DEFCON_LABELS[1]} (${DEFCON_PCT_RANGE[1]})`,
            color: rampColors[0],
          },
        ],
      },
      series: [
        {
          type: "heatmap",
          data: cells,
          label: {
            show: true,
            fontSize: 10,
            // White text with a dark halo stays legible on every DEFCON color.
            color: "#fff",
            textBorderColor: "rgba(0,0,0,0.55)",
            textBorderWidth: 2,
            formatter: (params: { data: HeatmapCell }) =>
              params.data ? formatPercentage(params.data.value[2], 0) : "",
          },
          emphasis: {
            itemStyle: {
              shadowBlur: 10,
              shadowColor: "rgba(0, 0, 0, 0.5)",
            },
          },
        },
      ],
    };
  }, [matrix, textColor]);
}
