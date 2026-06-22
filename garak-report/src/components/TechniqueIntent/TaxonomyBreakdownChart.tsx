/**
 * @file TaxonomyBreakdownChart.tsx
 * @description Sortable horizontal bar chart for a flat taxonomy score map
 *              (used for both the technique and intent breakdowns).
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import ReactECharts from "echarts-for-react";
import type { ECElementEvent } from "echarts";
import type { TaxonomyScoreMap } from "../../types/ReportEntry";
import {
  useTaxonomyBreakdownChartOptions,
  type BarDatum,
} from "../../hooks/useTaxonomyBreakdownChartOptions";
import type { MatrixLevel } from "../../utils/techniqueIntentRollup";
import type { TaxonomyDetail, TaxonomyHover } from "./types";

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
  /** Roll-up level of the linked heatmap (so bar keys normalize to match). */
  level?: MatrixLevel;
  /** Current coordinated-hover selection (active-level keys), or null. */
  hover?: TaxonomyHover | null;
  /** Emits this chart's hover as an active-level key, or null to clear. */
  onHover?: (hover: TaxonomyHover | null) => void;
}

/**
 * Vertical bar chart of taxonomy pass rates, sorted worst-first (left = most
 * vulnerable). Bars are colored by the colorblind-safe risk ramp for
 * consistency with the heatmap, and span the full width of their row.
 */
const TaxonomyBreakdownChart = ({
  data,
  kind,
  isDark,
  onSelect,
  aggregationLabel,
  level,
  hover,
  onHover,
}: TaxonomyBreakdownChartProps) => {
  // This chart only owns its own axis: a technique chart dims on the hovered
  // technique, an intent chart on the hovered intent; a cross-axis hover leaves
  // it untouched (activeKey null).
  const activeKey = (kind === "technique" ? hover?.technique : hover?.intent) ?? null;
  const option = useTaxonomyBreakdownChartOptions(data, kind, isDark, aggregationLabel, {
    activeKey,
    level,
  });
  // Compact fixed height; the rotated category axis grows horizontally with the
  // data, so the chart never needs the extra vertical room it had before.
  const height = 300;

  const detailOf = (d: BarDatum): TaxonomyDetail => ({
    kind,
    title: d.fullLabel,
    subtitle: kind === "technique" ? "Technique" : "Intent",
    score: d.score,
    nEvaluations: d.nEvaluations,
    detectors: d.detectors,
    probes: d.probes,
  });

  // Resolves the bar behind an event: the series item directly, or — when the
  // category label is hovered/clicked — by matching the label's index. The axis
  // categories and series data share the same order, and the per-bar `label` is
  // replaced by an ECharts config object, so we match on order, not on `label`.
  const barFor = (params: ECElementEvent): BarDatum | undefined => {
    if (params.componentType === "series") return params.data as BarDatum | undefined;
    if (params.componentType === "xAxis") {
      const idx = (option.xAxis.data as string[]).indexOf(params.value as string);
      if (idx >= 0) return option.series[0].data[idx] as unknown as BarDatum;
    }
    return undefined;
  };

  // Clicking a bar OR its category label opens the drill-down.
  const handleClick = (params: ECElementEvent) => {
    const d = barFor(params);
    if (d) onSelect?.(detailOf(d));
  };

  // Hovering a bar OR its category label highlights the matching heatmap
  // row/column. Bars are already rolled up to the heatmap's level, so the key
  // matches a row/column directly.
  const handleHover = (params: ECElementEvent) => {
    const d = barFor(params);
    if (!d) return;
    onHover?.(kind === "technique" ? { technique: d.key } : { intent: d.key });
  };

  const handleClear = () => onHover?.(null);

  return (
    <ReactECharts
      option={option}
      style={{ height, width: "100%" }}
      onEvents={{ click: handleClick, mouseover: handleHover, globalout: handleClear }}
    />
  );
};

export default TaxonomyBreakdownChart;
