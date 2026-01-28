/**
 * @file ProbesChart.tsx
 * @description Main probe visualization component combining bar chart and detector views.
 *              Orchestrates probe selection and detail display.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import DetectorsView from "./DetectorsView";
import useSeverityColor from "../hooks/useSeverityColor";
import type { ProbesChartProps } from "../types/ProbesChart";
import { Grid } from "@kui/react";
import { ProbeChartHeader, ProbeTagsList, ProbeBarChart } from "./ProbeChart";

/**
 * Main probe visualization component displaying bar chart and detector details.
 * Shows probe scores with optional detector comparison view when a probe is selected.
 *
 * @param props - Component props
 * @param props.module - Module data containing probes to display
 * @param props.selectedProbe - Currently selected probe or null
 * @param props.setSelectedProbe - Callback to update probe selection
 * @param props.isDark - Theme mode for chart styling
 * @returns Probe chart with optional detector detail panel
 */
const ProbesChart = ({
  module,
  selectedProbe,
  setSelectedProbe,
  isDark,
}: ProbesChartProps & { isDark?: boolean }) => {
  const { getSeverityColorByLevel, getSeverityLabelByLevel } = useSeverityColor();

  const probesData = useMemo(() => {
    // Sort probes alphabetically by class name for consistent ordering
    const sortedProbes = [...module.probes].sort((a, b) => {
      const nameA = (a.summary?.probe_name ?? a.probe_name).split('.').slice(1).join('.');
      const nameB = (b.summary?.probe_name ?? b.probe_name).split('.').slice(1).join('.');
      return nameA.localeCompare(nameB);
    });

    return sortedProbes.map(probe => {
      const score = probe.summary?.probe_score ?? 0;
      const name = probe.summary?.probe_name ?? probe.probe_name;
      const severity = probe.summary?.probe_severity;

      return {
        ...probe,
        label: name,
        value: score * 100,
        color: getSeverityColorByLevel(severity),
        severity,
        severityLabel: getSeverityLabelByLevel(severity),
      };
    });
  }, [module, getSeverityColorByLevel, getSeverityLabelByLevel]);

  const filtered = probesData;

  // Collect all unique tags from all probes in this module
  const allTags = useMemo(() => {
    const tagSet = new Set<string>();
    module.probes.forEach(probe => {
      probe.summary?.probe_tags?.forEach(tag => tagSet.add(tag));
    });
    return Array.from(tagSet).sort();
  }, [module.probes]);

  return (
    <>
      {filtered.length === 0 ? (
        <p className="text-sm italic text-gray-500 py-8">No probes meet the current filter.</p>
      ) : (
        <Grid cols={selectedProbe ? 2 : 1}>
          <div>
            <ProbeChartHeader />
            <ProbeTagsList tags={allTags} />
            <ProbeBarChart
              probesData={filtered}
              selectedProbe={selectedProbe}
              onProbeClick={setSelectedProbe}
              allProbes={module.probes}
              isDark={isDark}
            />
          </div>
          {selectedProbe && (
            <DetectorsView
              probe={selectedProbe}
              allProbes={module.probes}
              setSelectedProbe={setSelectedProbe}
              isDark={isDark}
              data-testid="detectors-view"
            />
          )}
        </Grid>
      )}
    </>
  );
};

export default ProbesChart;
