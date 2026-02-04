/**
 * @file useGroupedDetectors.ts
 * @description Hook to group detector results by type for cross-probe comparison.
 *              Enables the lollipop chart visualization of detector performance.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import theme from "../styles/theme";
import useSeverityColor from "./useSeverityColor";
import type { Probe } from "../types/ProbesChart";
import type { GroupedDetectorEntry, GroupedDetectors } from "../types/Detector";

// Re-export for backward compatibility
export type { GroupedDetectorEntry, GroupedDetectors } from "../types/Detector";

/**
 * Groups detector results across all probes for comparison visualization.
 *
 * This enables the "lollipop chart" comparison view where we can see how different
 * models perform on the same detector. Each detector type becomes a separate chart
 * showing Z-scores across all tested probes/models.
 *
 * @param probe - The selected probe to analyze
 * @param allProbes - All probes in the module for cross-probe comparison
 * @returns Map of detector types to their results across all probes
 *
 * @example
 * ```tsx
 * const grouped = useGroupedDetectors(selectedProbe, moduleProbes);
 * // Returns: { "detectorA": [{ label: "model1", zscore: 1.2, ... }], ... }
 * ```
 */
export const useGroupedDetectors = (probe: Probe, allProbes: Probe[]): GroupedDetectors => {
  const { getSeverityColorByComment } = useSeverityColor();

  return useMemo(() => {
    const map: GroupedDetectors = {};

    // Only show detector sections for detectors the selected probe actually has
    for (const selectedDetector of probe.detectors) {
      const detectorType = selectedDetector.detector_name;
      const matchingEntries: GroupedDetectorEntry[] = [];

      for (const p of allProbes) {
        const match = p.detectors.find(d => d.detector_name === detectorType);
        const relativeScore = match?.relative_score;
        const zMissing = relativeScore == null || isNaN(relativeScore);

        const color = zMissing
          ? theme.colors.tk150
          : getSeverityColorByComment(match!.relative_comment ?? "");

        const parts = p.probe_name.split(".");
        const label = parts.length > 1 ? parts.slice(1).join(".") : parts[0];

        matchingEntries.push({
          probeName: p.probe_name,
          label,
          zscore: zMissing ? null : relativeScore!,
          detector_score: match?.absolute_score ? match.absolute_score * 100 : null,
          comment: match?.relative_comment ?? "Unavailable",
          // Support both new (total_evaluated/passed) and old (attempt_count/hit_count) field names
          total_evaluated: match?.total_evaluated ?? match?.attempt_count ?? null,
          passed: match?.passed ?? (match?.attempt_count != null && match?.hit_count != null 
            ? match.attempt_count - match.hit_count 
            : null),
          color: color,
          unavailable: zMissing,
          detector_defcon: match?.detector_defcon ?? null,
          absolute_defcon: match?.absolute_defcon ?? null,
          relative_defcon: match?.relative_defcon ?? null,
        });
      }

      if (matchingEntries.length > 0) {
        map[detectorType] = matchingEntries;
      }
    }

    return map;
  }, [probe, allProbes, getSeverityColorByComment]);
};
