/**
 * @file useTechniqueIntentHeatmapOptions.ts
 * @description Hook to build ECharts options for the technique x intent heatmap.
 *              Consumes a pre-built {@link MatrixView}, so the same renderer
 *              serves both the leaf and grouped (worst-case roll-up) levels.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import {
  THEME_COLORS,
  ABSOLUTE_DEFCON_BOUNDS,
  DEFCON_LABELS,
  DEFCON_PCT_RANGE,
  CHART_DIMENSIONS,
  scoreToDefcon,
} from "../constants";
import { formatPercentage } from "../utils/formatPercentage";
import useSeverityColor from "./useSeverityColor";
import type { MatrixView, MatrixLeaf } from "../utils/techniqueIntentRollup";

/** WCAG relative luminance (0=black .. 1=white) of a #rrggbb color. */
const luminance = (hex: string): number => {
  const m = hex.replace("#", "");
  if (m.length < 6) return 1; // unknown/empty -> treat as light so text stays dark
  const channels = [0, 2, 4]
    .map(i => parseInt(m.slice(i, i + 2), 16) / 255)
    .map(c => (c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)));
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
};

/**
 * Picks near-black or white text for the best contrast against a cell color.
 * Threshold tuned for the KUI risk ramp: white only on the deep red/blue ends,
 * dark on the brighter orange/gold/light-blue mids (all ≥4.7:1 against #111827).
 */
const contrastText = (hex: string): string => (luminance(hex) > 0.22 ? "#111827" : "#ffffff");

/** DEFCON bucket boundaries as pass-rate percentages (mirrors scoreToDefcon). */
const PCT_BOUNDS = {
  TERRIBLE: ABSOLUTE_DEFCON_BOUNDS.TERRIBLE * 100,
  BELOW_AVG: ABSOLUTE_DEFCON_BOUNDS.BELOW_AVG * 100,
  ABOVE_AVG: ABSOLUTE_DEFCON_BOUNDS.ABOVE_AVG * 100,
  EXCELLENT: ABSOLUTE_DEFCON_BOUNDS.EXCELLENT * 100,
};

export interface HeatmapCell {
  value: [number, number, number | null];
  rowKey: string;
  colKey: string;
  rowLabel: string;
  colLabel: string;
  score: number;
  nEvaluations: number;
  leafCount: number;
  detectors: string[];
  leaves: MatrixLeaf[];
  /** True for a technique×intent pair that was never evaluated (renders N/A). */
  empty?: boolean;
}

/** Neutral cell fill/text for un-evaluated (N/A) pairs, by theme (KUI grays). */
const EMPTY_CELL = {
  dark: { fill: "#313131", text: "#a7a7a7" }, // gray-800 / gray-300
  light: { fill: "#eeeeee", text: "#757575" }, // gray-050 / gray-500
} as const;

/**
 * Builds ECharts options for a technique (rows) x intent (columns) heatmap.
 * Grouped cells are colored by their worst leaf, so a rolled-up cell never
 * reads safer than its most-vulnerable child. Risk is ordered top-left.
 *
 * @param view - Pre-built matrix view (leaf or grouped)
 * @param isDark - Whether dark theme is active
 * @returns ECharts option configuration object
 */
export function useTechniqueIntentHeatmapOptions(view: MatrixView, isDark?: boolean) {
  const textColor = isDark ? THEME_COLORS.text.dark : THEME_COLORS.text.light;
  const { getRiskRampColor } = useSeverityColor();

  return useMemo(() => {
    // Monotonic warm→cool risk ramp (DC-1..DC-5). The matrix encodes a
    // sequential pass-rate, so it uses an ordered gradient rather than the
    // categorical DEFCON palette used by the badges/other charts.
    const rampColors = [1, 2, 3, 4, 5].map(d => getRiskRampColor(d));

    const empty = isDark ? EMPTY_CELL.dark : EMPTY_CELL.light;

    const { rows, cols } = view;
    const cells: HeatmapCell[] = [];
    rows.forEach((rowKey, yIndex) => {
      cols.forEach((colKey, xIndex) => {
        const c = view.cell(rowKey, colKey);
        const base = {
          rowKey,
          colKey,
          rowLabel: view.rowLabel(rowKey),
          colLabel: view.colLabel(colKey),
        };
        if (!c) {
          // Pair never evaluated: render an explicit N/A cell so a gap is never
          // mistaken for a 0% (complete-failure) result.
          cells.push({
            ...base,
            value: [xIndex, yIndex, null],
            score: NaN,
            nEvaluations: 0,
            leafCount: 0,
            detectors: [],
            leaves: [],
            empty: true,
          });
          return;
        }
        cells.push({
          ...base,
          value: [xIndex, yIndex, Math.round(c.score * 100 * 100) / 100],
          score: c.score,
          nEvaluations: c.nEvaluations,
          leafCount: c.leafCount,
          detectors: c.detectors,
          leaves: c.leaves,
        });
      });
    });

    return {
      tooltip: {
        trigger: "item",
        confine: true,
        // Heatmap tooltips anchor to the cell by default; follow the cursor
        // instead (offset so the pointer never covers the text).
        position: (point: number[]) => [point[0] + 12, point[1] + 12],
        formatter: (params: { data: HeatmapCell }) => {
          const d = params.data;
          if (!d) return "";
          if (d.empty) {
            return (
              `<strong>${d.rowLabel}</strong><br/>` +
              `<span style="opacity:0.75">Intent: ${d.colLabel}</span><br/>` +
              `<span style="opacity:0.75">Not evaluated (no technique×intent pair)</span>`
            );
          }
          const pooled =
            d.leafCount > 1
              ? `<span style="opacity:0.75">Worst of ${d.leafCount} technique×intent pairs</span><br/>`
              : "";
          return (
            `<strong>${d.rowLabel}</strong><br/>` +
            `<span style="opacity:0.75">Intent: ${d.colLabel}</span><br/>` +
            pooled +
            `Pass rate: ${formatPercentage(d.value[2] ?? 0)}<br/>` +
            `Evaluations: ${d.nEvaluations.toLocaleString()}<br/>` +
            `<span style="opacity:0.6">Click to drill down</span>`
          );
        },
      },
      // Shared grid, but leave extra bottom room for the horizontal legend.
      grid: { ...CHART_DIMENSIONS.grid, bottom: 60 },
      xAxis: {
        type: "category",
        data: cols.map(view.colLabel),
        splitArea: { show: true },
        axisLabel: {
          rotate: CHART_DIMENSIONS.axis.labelRotation,
          interval: 0,
          fontSize: 12,
          color: textColor,
        },
        axisLine: { lineStyle: { color: textColor } },
      },
      yAxis: {
        type: "category",
        // Worst-first rows live at index 0; invert so they render at the top.
        inverse: true,
        data: rows.map(view.rowLabel),
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
          // Each cell carries its own fixed label colour (dark on light cells,
          // white on dark cells), pinned in BOTH the normal and emphasis states
          // so hover can't make ECharts inherit the cell fill (blue-on-blue).
          // N/A cells get an explicit neutral fill + "N/A" label so a gap never
          // reads as a 0% result.
          data: cells.map(c => {
            if (c.empty) {
              return {
                ...c,
                itemStyle: { color: empty.fill },
                label: { color: empty.text, formatter: () => "N/A" },
                emphasis: { label: { color: empty.text } },
              };
            }
            const lbl = contrastText(rampColors[scoreToDefcon(c.score) - 1] ?? "");
            return {
              ...c,
              label: { color: lbl },
              emphasis: { label: { color: lbl } },
            };
          }),
          label: {
            show: true,
            fontSize: 13,
            fontWeight: 700,
            formatter: (params: { data: HeatmapCell }) =>
              params.data && params.data.value[2] != null
                ? formatPercentage(params.data.value[2], 0)
                : "",
          },
          // Hover affordance: outline the hovered cell only. No `focus` (so other
          // cells aren't dimmed) and no label restyle here (the per-cell label
          // colour above carries through), so nothing flashes or recolours.
          emphasis: {
            itemStyle: {
              borderColor: isDark ? "#ffffff" : "#111827",
              borderWidth: 2,
              shadowBlur: 8,
              shadowColor: "rgba(0, 0, 0, 0.45)",
            },
          },
        },
      ],
    };
  }, [view, isDark, textColor, getRiskRampColor]);
}
