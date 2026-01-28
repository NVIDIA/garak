/**
 * @file DetectorsView.tsx
 * @description Panel component displaying detector comparison charts for a selected probe.
 *              Groups detectors by type and provides filtering controls.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useState } from "react";
import { useGroupedDetectors } from "../hooks/useGroupedDetectors";
import type { Probe } from "../types/ProbesChart";
import { Stack, Panel, Flex, Checkbox } from "@kui/react";
import { DetectorChartHeader, DetectorFilters, DetectorLollipopChart } from "./DetectorChart";
import { DEFCON_LEVELS, CHART_OPACITY } from "../constants";

/**
 * Panel displaying detector comparison charts grouped by detector type.
 * Provides DEFCON filtering and N/A visibility toggle.
 *
 * @param props - Component props
 * @param props.probe - Selected probe to show detectors for
 * @param props.allProbes - All probes for cross-comparison
 * @param props.setSelectedProbe - Callback to change selected probe
 * @param props.isDark - Theme mode for chart styling
 * @returns Detector comparison panel with filter controls
 */
const DetectorsView = ({
  probe,
  allProbes,
  setSelectedProbe,
  isDark,
}: {
  probe: Probe;
  allProbes: Probe[];
  setSelectedProbe: (p: Probe) => void;
  isDark?: boolean;
}) => {
  const [hideUnavailable, setHideUnavailable] = useState(false);
  const [selectedDefconByDetector, setSelectedDefconByDetector] = useState<
    Record<string, number[]>
  >({});
  const groupedDetectors = useGroupedDetectors(probe, allProbes);

  const toggleDefconForDetector = (detectorType: string, defcon: number) => {
    setSelectedDefconByDetector(prev => {
      const currentSelected = prev[detectorType] || [...DEFCON_LEVELS];
      const newSelected = currentSelected.includes(defcon)
        ? currentSelected.filter(d => d !== defcon)
        : [...currentSelected, defcon].sort();

      return {
        ...prev,
        [detectorType]: newSelected,
      };
    });
  };

  const getDefconOpacity = (detectorType: string, defcon: number): number => {
    const selected = selectedDefconByDetector[detectorType] || [...DEFCON_LEVELS];
    return selected.includes(defcon) ? CHART_OPACITY.full : CHART_OPACITY.dimmed;
  };

  return (
    <Panel
      slotHeading={<DetectorChartHeader />}
      slotFooter={
        <Flex justify="end" gap="density-xs">
          <Checkbox
            checked={hideUnavailable}
            onCheckedChange={() => setHideUnavailable(!hideUnavailable)}
            slotLabel="Hide N/A"
          />
        </Flex>
      }
    >
      {[...Object.entries(groupedDetectors)]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([detectorType, entries]) => {
          const selectedDefcons = selectedDefconByDetector[detectorType] || [...DEFCON_LEVELS];
          const filteredEntries = entries.filter(entry => {
            if (hideUnavailable && entry.unavailable) return false;
            if (entry.detector_defcon && !selectedDefcons.includes(entry.detector_defcon))
              return false;
            return true;
          });

          return (
            <Stack key={detectorType} paddingBottom="density-3xl">
              <Stack>
                <DetectorFilters
                  entries={entries}
                  onToggleDefcon={defcon => toggleDefconForDetector(detectorType, defcon)}
                  getDefconOpacity={defcon => getDefconOpacity(detectorType, defcon)}
                />

                <DetectorLollipopChart
                  probe={probe}
                  allProbes={allProbes}
                  detectorType={detectorType}
                  entries={filteredEntries}
                  hideUnavailable={hideUnavailable}
                  onProbeClick={setSelectedProbe}
                  isDark={isDark}
                />
              </Stack>
            </Stack>
          );
        })}
    </Panel>
  );
};

export default DetectorsView;
