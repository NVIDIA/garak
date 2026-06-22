/**
 * @file TechniqueIntentHeatmap.tsx
 * @description Technique x Intent heatmap (pass-rate matrix) rendered with ECharts.
 *              Renders a pre-built MatrixView, so the same component shows both
 *              the leaf level and the grouped (worst-case roll-up) level.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useEffect, useRef } from "react";
import ReactECharts from "echarts-for-react";
import type { ECElementEvent } from "echarts";
import {
  useTechniqueIntentHeatmapOptions,
  type HeatmapCell,
} from "../../hooks/useTechniqueIntentHeatmapOptions";
import type { MatrixView } from "../../utils/techniqueIntentRollup";
import { shortenTechnique } from "../../utils/taxonomyLabels";
import type { TaxonomyDetail, TaxonomyHover } from "./types";

/** Props for TechniqueIntentHeatmap component */
interface TechniqueIntentHeatmapProps {
  /** Pre-built matrix view (leaf or grouped roll-up). */
  view: MatrixView;
  /** Theme mode for styling */
  isDark?: boolean;
  /** Called when a cell is clicked, to open the drill-down. */
  onSelect?: (detail: TaxonomyDetail) => void;
  /** Current coordinated-hover selection (active-level keys), or null. */
  hover?: TaxonomyHover | null;
  /** Emits the hovered cell's row/column keys, or null to clear. */
  onHover?: (hover: TaxonomyHover | null) => void;
}

/**
 * Renders a technique (rows) x intent (columns) heatmap colored by pass rate.
 * Height grows with the number of rows so they stay readable.
 * Clicking a cell opens the drill-down via onSelect.
 */
const TechniqueIntentHeatmap = ({
  view,
  isDark,
  onSelect,
  hover,
  onHover,
}: TechniqueIntentHeatmapProps) => {
  const option = useTechniqueIntentHeatmapOptions(view, isDark);
  const height = Math.max(280, view.rows.length * 34 + 140);
  const chartRef = useRef<ReactECharts>(null);

  // Coordinated highlight, driven imperatively so it never rebuilds the chart
  // (which would flash the labels). A technique hover outlines the whole matching
  // row, an intent hover the whole column, using the same emphasis as cell hover.
  useEffect(() => {
    const inst = chartRef.current?.getEchartsInstance();
    if (!inst) return;
    inst.dispatchAction({ type: "downplay", seriesIndex: 0 });
    const tech = hover?.technique ?? null;
    const intent = hover?.intent ?? null;
    if (tech == null && intent == null) return;
    const cells = (option.series[0].data ?? []) as HeatmapCell[];
    const dataIndex = cells.reduce<number[]>((acc, c, i) => {
      if ((tech == null || c.rowKey === tech) && (intent == null || c.colKey === intent)) acc.push(i);
      return acc;
    }, []);
    if (dataIndex.length) inst.dispatchAction({ type: "highlight", seriesIndex: 0, dataIndex });
  }, [hover, option]);

  const detailOf = (d: HeatmapCell): TaxonomyDetail => ({
    kind: "cell",
    title: d.rowLabel,
    subtitle: `Intent: ${d.colLabel}`,
    score: d.score,
    nEvaluations: d.nEvaluations,
    detectors: d.detectors,
    leaves:
      d.leafCount > 1
        ? d.leaves.map(l => ({
            label: `${shortenTechnique(l.technique)} × ${l.intent}`,
            score: l.score,
            nEvaluations: l.nEvaluations,
          }))
        : undefined,
  });

  const handleClick = (params: ECElementEvent) => {
    const d = params.data as HeatmapCell | undefined;
    if (d && !d.empty) onSelect?.(detailOf(d)); // N/A cells have nothing to drill into
  };

  // Hovering a cell lights up the matching technique + intent bars; the option
  // doesn't depend on `hover`, so this never re-renders/flashes the heatmap.
  const handleHover = (params: ECElementEvent) => {
    const d = params.data as HeatmapCell | undefined;
    if (d) onHover?.({ technique: d.rowKey, intent: d.colKey });
  };

  const handleClear = () => onHover?.(null);

  return (
    <ReactECharts
      ref={chartRef}
      option={option}
      style={{ height, width: "100%" }}
      onEvents={{ click: handleClick, mouseover: handleHover, globalout: handleClear }}
    />
  );
};

export default TechniqueIntentHeatmap;
