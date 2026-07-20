/**
 * @file ProbesChart.tsx
 * @description Main probe visualization component combining bar chart and detector views.
 *              Orchestrates probe selection and detail display.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo, useState } from "react";
import DetectorsView from "./DetectorsView";
import useSeverityColor from "../hooks/useSeverityColor";
import type { ProbesChartProps } from "../types/ProbesChart";
import { Grid, Stack } from "@kui/react";
import { ProbeChartHeader, ProbeTagsList, ProbeBarChart, ModuleFilterChips } from "./ProbeChart";

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
  const [selectedModules, setSelectedModules] = useState<string[]>([]);

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

  // Extract unique module names (first part of probe name before the dot)
  const moduleNames = useMemo(() => {
    const moduleSet = new Set<string>();
    probesData.forEach(probe => {
      const moduleName = probe.label.split(".")[0];
      if (moduleName) moduleSet.add(moduleName);
    });
    return Array.from(moduleSet).sort();
  }, [probesData]);

  // Filter probes by selected modules (multi-select)
  const filtered = useMemo(() => {
    if (selectedModules.length === 0) return probesData;
    return probesData.filter(probe => {
      const moduleName = probe.label.split(".")[0];
      return selectedModules.includes(moduleName);
    });
  }, [probesData, selectedModules]);

  // Handle module chip click - toggle in multi-select array
  const handleModuleClick = (moduleName: string) => {
    setSelectedModules(prev => 
      prev.includes(moduleName)
        ? prev.filter(m => m !== moduleName)
        : [...prev, moduleName]
    );
    setSelectedProbe(null); // Clear probe selection when changing module filter
  };

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
          <Stack gap="density-md">
            <ProbeChartHeader />
            <ProbeTagsList tags={allTags} />
            <ModuleFilterChips
              moduleNames={moduleNames}
              selectedModules={selectedModules}
              onSelectModule={handleModuleClick}
            />
            <ProbeBarChart
              probesData={filtered}
              selectedProbe={selectedProbe}
              onProbeClick={setSelectedProbe}
              allProbes={module.probes}
              isDark={isDark}
              allModuleNames={moduleNames}
            />
          </Stack>
          {selectedProbe && (
            <DetectorsView
              probe={selectedProbe}
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
