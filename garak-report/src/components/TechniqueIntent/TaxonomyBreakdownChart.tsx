/**
 * @file TaxonomyBreakdownChart.tsx
 * @description Sortable horizontal bar chart for a flat taxonomy score map
 *              (used for both the technique and intent breakdowns).
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import ReactECharts from "echarts-for-react";
import type { ECElementEvent } from "echarts";
import type { TaxonomyScoreMap } from "../../types/ReportEntry";
import { scoreToDefcon, THEME_COLORS, RISK_RAMP_COLORS } from "../../constants";
import { formatPercentage } from "../../utils/formatPercentage";
import { shortenTechnique, formatTechniqueFull } from "../../utils/taxonomyLabels";
import type { TaxonomyDetail } from "./types";

/** Props for TaxonomyBreakdownChart component */
interface TaxonomyBreakdownChartProps {
  /** Flat taxonomy map (intent code or `demon:` technique -> score) */
  data: TaxonomyScoreMap;
  /** Determines label/tooltip formatting */
  kind: "technique" | "intent";
  /** Theme mode for styling */
  isDark?: boolean;
  /** Called when a bar is clicked, to open the drill-down. */
  onSelect?: (detail: TaxonomyDetail) => void;
  /** Human-readable name of the aggregation behind each score (for the tooltip). */
  aggregationLabel?: string;
}

/** Abbreviates large evaluation counts for inline labels (16740 -> "16.7k"). */
const compactCount = (n: number): string => {
  if (n >= 1000) return `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k`;
  return n.toLocaleString();
};

interface BarDatum {
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
 * Horizontal bar chart of taxonomy pass rates, sorted worst-first (top = most
 * vulnerable). Bars are colored by DEFCON severity for consistency with the
 * rest of the report.
 */
const TaxonomyBreakdownChart = ({
  data,
  kind,
  isDark,
  onSelect,
  aggregationLabel,
}: TaxonomyBreakdownChartProps) => {
  const textColor = isDark ? THEME_COLORS.text.dark : THEME_COLORS.text.light;

  const bars = useMemo<BarDatum[]>(() => {
    return Object.entries(data)
      .map(([key, entry]) => ({
        key,
        label: kind === "technique" ? shortenTechnique(key) : key,
        fullLabel: kind === "technique" ? formatTechniqueFull(key) : key,
        value: Math.round(entry.score * 100 * 100) / 100,
        score: entry.score,
        color: RISK_RAMP_COLORS[scoreToDefcon(entry.score)],
        nEvaluations: entry.n_evaluations,
        probes: entry.probes ?? [],
        detectors: entry.detectors_used ?? [],
      }))
      .sort((a, b) => a.value - b.value);
  }, [data, kind]);

  const handleClick = (params: ECElementEvent) => {
    const d = params.data as BarDatum | undefined;
    if (!d || !onSelect) return;
    onSelect({
      kind,
      title: d.fullLabel,
      subtitle: kind === "technique" ? "Technique" : "Intent",
      score: d.score,
      nEvaluations: d.nEvaluations,
      detectors: d.detectors,
      probes: d.probes,
    });
  };

  const option = useMemo(
    () => ({
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
      grid: { containLabel: true, left: 10, right: 96, top: 10, bottom: 10 },
      xAxis: {
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
      yAxis: {
        type: "category",
        inverse: true,
        data: bars.map(b => b.label),
        axisLabel: { color: textColor, fontSize: 12 },
        axisLine: { lineStyle: { color: textColor } },
      },
      series: [
        {
          type: "bar",
          barMaxWidth: 24,
          data: bars.map(b => ({
            ...b,
            value: b.value,
            itemStyle: { color: b.color },
            label: {
              show: true,
              position: "right",
              formatter: (p: { data: BarDatum }) =>
                `${formatPercentage(p.data.value, 0)}  ·  n=${compactCount(p.data.nEvaluations)}`,
              fontSize: 11,
              color: textColor,
            },
          })),
        },
      ],
    }),
    [bars, textColor, isDark, aggregationLabel],
  );

  const height = Math.max(160, bars.length * 30 + 60);

  return (
    <ReactECharts
      option={option}
      style={{ height, width: "100%" }}
      onEvents={{ click: handleClick }}
    />
  );
};

export default TaxonomyBreakdownChart;
