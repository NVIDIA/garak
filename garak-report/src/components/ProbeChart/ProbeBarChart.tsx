/**
 * @file ProbeBarChart.tsx
 * @description Bar chart component displaying probe scores with severity coloring.
 *              Handles click interactions for probe selection.
 * @module components/ProbeChart
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import ReactECharts from "echarts-for-react";
import type { ECElementEvent } from "echarts";
import type { Probe } from "../../types/ProbesChart";
import { useProbeChartOptions, type EnrichedProbeData } from "../../hooks/useProbeChartOptions";

/** Props for ProbeBarChart component */
interface ProbeBarChartProps {
  /** Enriched probe data with display properties */
  probesData: EnrichedProbeData[];
  /** Currently selected probe or null */
  selectedProbe: Probe | null;
  /** Callback when a probe is clicked */
  onProbeClick: (probe: Probe | null) => void;
  /** All probes for name matching on axis click */
  allProbes: Probe[];
  /** Theme mode for styling */
  isDark?: boolean;
  /** All module names for consistent color mapping (not affected by filtering) */
  allModuleNames?: string[];
}

/**
 * Bar chart displaying probe scores with click-to-select functionality.
 * Highlights selected probe and dims others for visual focus.
 *
 * @param props - Component props
 * @param props.probesData - Enriched probe data with display properties
 * @param props.selectedProbe - Currently selected probe or null
 * @param props.onProbeClick - Callback when a probe bar is clicked
 * @param props.allProbes - All probes for name matching on click
 * @param props.isDark - Theme mode for styling
 * @returns ECharts bar chart with click handling
 */
const ProbeBarChart = ({
  probesData,
  selectedProbe,
  onProbeClick,
  allProbes,
  isDark,
  allModuleNames,
}: ProbeBarChartProps) => {
  const option = useProbeChartOptions(probesData, selectedProbe, isDark, allModuleNames);

  /**
   * Handles click events on chart bars or axis labels.
   * Matches clicked item to probe and toggles selection.
   */
  const handleClick = (params: ECElementEvent) => {
    let probeName = params.name;

    // Handle axis label clicks
    if (params.componentType === "xAxis") {
      const shortLabel = typeof params.value === "string" ? params.value : String(params.value);

      const matchingProbe = allProbes.find(p => {
        const fullName = p.summary?.probe_name || "";
        const [, ...rest] = fullName.split(".");
        const shortName = rest.join(".");
        return shortName === shortLabel;
      });

      if (matchingProbe) {
        probeName = matchingProbe.summary?.probe_name;
      } else {
        const directMatch = allProbes.find(p => p.summary?.probe_name?.includes(shortLabel));
        if (directMatch) {
          probeName = directMatch.summary?.probe_name;
        }
      }
    }

    // Find and toggle selection
    const clicked = allProbes.find(p => p.summary?.probe_name === probeName);
    if (clicked) {
      onProbeClick(
        selectedProbe?.summary?.probe_name === clicked.summary?.probe_name ? null : clicked
      );
    }
  };

  return <ReactECharts option={option} onEvents={{ click: handleClick }} />;
};

export default ProbeBarChart;
