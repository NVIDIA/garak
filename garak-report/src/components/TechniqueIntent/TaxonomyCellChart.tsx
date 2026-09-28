/**
 * @file TaxonomyCellChart.tsx
 * @description Horizontal bar chart of a group's cross-axis pass rates (e.g. a
 *              technique's intents), worst-first and DEFCON-coloured. Clicking a
 *              bar (or its axis label) selects that pairing so the parent can
 *              show its detectors — the same "expand → bar chart → click for
 *              detail" flow the Modules tab uses for module → probes.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import ReactECharts from "echarts-for-react";
import type { ECElementEvent } from "echarts";
import { useTaxonomyCellChartOptions } from "../../hooks/useTaxonomyCellChartOptions";
import type { AxisCell } from "../../utils/techniqueIntentRollup";

/** Props for TaxonomyCellChart component */
interface TaxonomyCellChartProps {
  /** Worst-first cross-axis cells to plot. */
  cells: AxisCell[];
  /** Theme mode for axis/label colours. */
  isDark?: boolean;
  /** Currently selected cell key, or null. */
  selectedKey: string | null;
  /** Toggles selection of a clicked bar. */
  onSelect: (key: string | null) => void;
}

/**
 * Renders one bar per cross-axis pairing, delegating the option build to
 * {@link useTaxonomyCellChartOptions} and handling click-to-select here.
 */
const TaxonomyCellChart = ({ cells, isDark, selectedKey, onSelect }: TaxonomyCellChartProps) => {
  const { option, height } = useTaxonomyCellChartOptions(cells, selectedKey, isDark);

  const handleClick = (params: ECElementEvent) => {
    // Axis-label clicks carry the label in `value` with no dataIndex; bar clicks
    // carry the dataIndex. Resolve both to the same cell so they behave alike.
    const cell =
      params.componentType === "yAxis"
        ? cells.find(c => c.otherLabel === params.value)
        : cells[params.dataIndex];
    if (cell) onSelect(selectedKey === cell.otherKey ? null : cell.otherKey);
  };

  return (
    <ReactECharts
      option={option}
      style={{ height, width: "100%" }}
      onEvents={{ click: handleClick }}
    />
  );
};

export default TaxonomyCellChart;
