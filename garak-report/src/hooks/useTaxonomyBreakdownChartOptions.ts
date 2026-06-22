/**
 * @file useTaxonomyBreakdownChartOptions.ts
 * @description Hook to build ECharts options for a 1D taxonomy breakdown
 *              (technique or intent) vertical bar chart. Mirrors the
 *              `use*ChartOptions` pattern used by the probe/detector charts.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import type { TaxonomyScoreMap } from "../types/ReportEntry";
import { scoreToDefcon, THEME_COLORS, CHART_DIMENSIONS } from "../constants";
import { formatPercentage } from "../utils/formatPercentage";
import { shortenTechnique, formatTechniqueFull, techniqueGroupLabel } from "../utils/taxonomyLabels";
import { rollupTaxonomyMap, type MatrixLevel } from "../utils/techniqueIntentRollup";
import useSeverityColor from "./useSeverityColor";

/** Opacity applied to bars that don't match the coordinated-hover selection. */
const DIMMED_OPACITY = 0.25;

/** Level + coordinated-hover options that keep the bars in sync with the heatmap. */
export interface BreakdownHoverOptions {
  /**
   * Active-level key that should stay highlighted on this chart's axis;
   * `null`/undefined means no dimming. Bars are rolled up to the same level as
   * the heatmap, so this is compared against each bar's key directly.
   */
  activeKey?: string | null;
  /** Roll-up level the heatmap is showing, so the bars share its categories. */
  level?: MatrixLevel;
}

export interface BarDatum {
  key: string;
  label: string;
  fullLabel: string;
  value: number;
  score: number;
  color: string;
  nEvaluations: number;
  probes: string[];
  detectors: string[];
}

/**
 * Builds ECharts options for a worst-first vertical bar chart of taxonomy
 * pass rates, colored by the colorblind-safe risk ramp. Mirrors the probe bar
 * chart: categories on the x-axis (rotated), pass rate on the y-axis.
 *
 * @param data - Flat taxonomy map (intent code or `demon:` technique -> score)
 * @param kind - Whether the keys are techniques or intents (label formatting)
 * @param isDark - Whether dark theme is active
 * @param aggregationLabel - Human-readable aggregation name (for the tooltip)
 */
export function useTaxonomyBreakdownChartOptions(
  data: TaxonomyScoreMap,
  kind: "technique" | "intent",
  isDark?: boolean,
  aggregationLabel?: string,
  hover?: BreakdownHoverOptions,
) {
  const textColor = isDark ? THEME_COLORS.text.dark : THEME_COLORS.text.light;
  const { getRiskRampColor } = useSeverityColor();
  const activeKey = hover?.activeKey ?? null;
  const level: MatrixLevel = hover?.level ?? "leaf";

  return useMemo(() => {
    // Roll the flat map up to the heatmap's level so the bars share its exact
    // categories; keys then match the heatmap row/column keys 1:1.
    const rolled = rollupTaxonomyMap(data, kind, level);
    const isDimmed = (key: string) => activeKey != null && key !== activeKey;

    // Label to match the heatmap axes: grouped techniques use the subcategory
    // breadcrumb, leaves the shortened tail; intent codes pass through verbatim.
    const labelOf = (key: string) =>
      kind === "intent" ? key : level === "grouped" ? techniqueGroupLabel(key) : shortenTechnique(key);
    const fullLabelOf = (key: string) =>
      kind === "intent" ? key : level === "grouped" ? techniqueGroupLabel(key) : formatTechniqueFull(key);

    // Worst-first: lowest pass rate sorts to the left.
    const bars: BarDatum[] = Object.entries(rolled)
      .map(([key, entry]) => ({
        key,
        label: labelOf(key),
        fullLabel: fullLabelOf(key),
        value: Math.round(entry.score * 100 * 100) / 100,
        score: entry.score,
        color: getRiskRampColor(scoreToDefcon(entry.score)),
        nEvaluations: entry.n_evaluations,
        probes: entry.probes ?? [],
        detectors: entry.detectors_used ?? [],
      }))
      .sort((a, b) => a.value - b.value);

    return {
      tooltip: {
        trigger: "item",
        confine: true,
        formatter: (params: { data: BarDatum }) => {
          const d = params.data;
          if (!d) return "";
          // NB: `d.label` is overridden by the ECharts label config object below,
          // so use `fullLabel` for the readable name here.
          const metric = aggregationLabel ?? "Pass rate";
          return (
            `<strong>${d.fullLabel}</strong><br/>` +
            `${metric.charAt(0).toUpperCase() + metric.slice(1)}: ${formatPercentage(d.value)}<br/>` +
            `Evaluations: ${d.nEvaluations.toLocaleString()}<br/>` +
            `<span style="opacity:0.6">Click to drill down</span>`
          );
        },
      },
      // Extra top headroom so the value label above a full-height (100%) bar
      // isn't clipped by the chart edge.
      grid: { ...CHART_DIMENSIONS.grid, top: 28 },
      xAxis: {
        type: "category",
        data: bars.map(b => b.label),
        // Emit mouseover events for the category labels too, so hovering a
        // label drives the same coordinated highlight as hovering its bar.
        triggerEvent: true,
        axisLabel: {
          rotate: CHART_DIMENSIONS.axis.labelRotation,
          interval: 0,
          fontSize: 12,
          color: textColor,
        },
        axisLine: { lineStyle: { color: textColor } },
      },
      yAxis: {
        type: "value",
        min: 0,
        max: 100,
        axisLabel: { color: textColor, formatter: "{value}%" },
        axisLine: { lineStyle: { color: textColor } },
        splitLine: {
          lineStyle: {
            color: isDark ? THEME_COLORS.chart.splitLine.dark : THEME_COLORS.chart.splitLine.light,
          },
        },
      },
      series: [
        {
          type: "bar",
          // Cap bar width (tighter than the probe chart) and keep a generous
          // category gap so a handful of buckets don't stretch into slabs.
          barMaxWidth: 48,
          barCategoryGap: "45%",
          data: bars.map(b => {
            const dimmed = isDimmed(b.key);
            return {
              ...b,
              value: b.value,
              itemStyle: { color: b.color, opacity: dimmed ? DIMMED_OPACITY : 1 },
              label: {
                show: true,
                position: "top",
                formatter: (p: { data: BarDatum }) => formatPercentage(p.data.value, 0),
                fontSize: 12,
                fontWeight: 600,
                // Label stays fully opaque even when the bar is de-emphasized, so
                // the value is always legible; only the bar fill dims.
                color: textColor,
              },
            };
          }),
        },
      ],
    };
  }, [data, kind, textColor, isDark, aggregationLabel, getRiskRampColor, activeKey, level]);
}
