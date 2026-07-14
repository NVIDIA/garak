/**
 * @file TechniqueIntentHeatmap.tsx
 * @description Technique x Intent heatmap (pass-rate matrix) rendered with ECharts.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import ReactECharts from "echarts-for-react";
import type { ECElementEvent } from "echarts";
import type { TechniqueIntentMatrix } from "../../types/ReportEntry";
import {
  useTechniqueIntentHeatmapOptions,
  type HeatmapCell,
} from "../../hooks/useTechniqueIntentHeatmapOptions";
import type { TaxonomyDetail } from "./types";

/** Props for TechniqueIntentHeatmap component */
interface TechniqueIntentHeatmapProps {
  /** Nested technique -> intent -> score matrix */
  matrix: TechniqueIntentMatrix;
  /** Theme mode for styling */
  isDark?: boolean;
  /** Called when a cell is clicked, to open the drill-down. */
  onSelect?: (detail: TaxonomyDetail) => void;
}

/**
 * Renders a technique (rows) x intent (columns) heatmap colored by pass rate.
 * Height grows with the number of techniques so rows stay readable.
 * Clicking a cell opens the drill-down via onSelect.
 */
const TechniqueIntentHeatmap = ({ matrix, isDark, onSelect }: TechniqueIntentHeatmapProps) => {
  const option = useTechniqueIntentHeatmapOptions(matrix, isDark);
  const rowCount = Object.keys(matrix).length;
  const height = Math.max(280, rowCount * 34 + 140);

  const handleClick = (params: ECElementEvent) => {
    const d = params.data as HeatmapCell | undefined;
    if (!d || !onSelect) return;
    onSelect({
      kind: "cell",
      title: d.techniqueFull,
      subtitle: `Intent: ${d.intentKey}`,
      score: d.score,
      nEvaluations: d.nEvaluations,
      detectors: d.detectors,
    });
  };

  return (
    <ReactECharts
      option={option}
      style={{ height, width: "100%" }}
      onEvents={{ click: handleClick }}
    />
  );
};

export default TechniqueIntentHeatmap;
