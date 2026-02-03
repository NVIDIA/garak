/**
 * @file DetectorsView.tsx
 * @description Panel component displaying probe analysis with detector breakdown.
 *              Shows probe header with severity, description, and failure stats,
 *              followed by detector results and relative performance (Z-score).
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useState } from "react";
import type { Probe } from "../types/ProbesChart";
import { Stack, Panel, Flex, Text, Badge } from "@kui/react";
import { DetectorLollipopChart } from "./DetectorChart";
import DetectorResultsTable from "./DetectorChart/DetectorResultsTable";
import DefconBadge from "./DefconBadge";
import useSeverityColor from "../hooks/useSeverityColor";

/**
 * Panel displaying probe analysis with detector breakdown.
 * Structure: Header (name + DEFCON + description + stats) → Detector Breakdown → Relative Performance
 *
 * @param props - Component props
 * @param props.probe - Selected probe to show detectors for
 * @param props.isDark - Theme mode for chart styling
 * @returns Probe analysis panel with detector comparison
 */
const DetectorsView = ({
  probe,
  isDark,
}: {
  probe: Probe;
  isDark?: boolean;
}) => {
  // Sort detectors alphabetically by name
  const sortedDetectors = [...probe.detectors].sort((a, b) =>
    a.detector_name.localeCompare(b.detector_name)
  );

  // Shared hover state for linked highlighting between chart and table
  const [hoveredDetector, setHoveredDetector] = useState<string | null>(null);

  const { getSeverityLabelByLevel, getDefconBadgeColor } = useSeverityColor();

  // Use data directly from backend - no calculations
  const probeSeverity = probe.summary?.probe_severity ?? 5;
  const promptCount = probe.summary?.prompt_count;
  const severityLabel = getSeverityLabelByLevel(probeSeverity);

  return (
    <Panel>
      <Stack gap="density-3xl">
        {/* Header group: name + severity + description + stats */}
        <Stack gap="density-md">
          <Flex gap="density-md" align="center">
            <DefconBadge defcon={probeSeverity} />
            <Text kind="title/lg">{probe.probe_name}</Text>
            <Badge color={getDefconBadgeColor(probeSeverity)} kind="outline">
              {severityLabel}
            </Badge>
          </Flex>

          {probe.summary?.probe_descr && (
            <Text kind="body/regular/md" style={{ color: "var(--color-tk-400)" }}>
              {probe.summary.probe_descr}
            </Text>
          )}

          {promptCount != null && (
            <Badge color="gray" kind="outline">
              {promptCount.toLocaleString()} prompts
            </Badge>
          )}
        </Stack>

        {/* Detector Breakdown */}
        <DetectorResultsTable
          detectors={sortedDetectors}
          hoveredDetector={hoveredDetector}
          onHoverDetector={setHoveredDetector}
        />

        {/* Relative Performance (Z-Score) */}
        <DetectorLollipopChart
          detectors={sortedDetectors}
          isDark={isDark}
          hoveredDetector={hoveredDetector}
          onHoverDetector={setHoveredDetector}
        />
      </Stack>
    </Panel>
  );
};

export default DetectorsView;
