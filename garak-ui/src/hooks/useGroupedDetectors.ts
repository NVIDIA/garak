import { useMemo } from "react";
import theme from "../styles/theme";
import useSeverityColor from "./useSeverityColor";
import type { Probe } from "../types/ProbesChart";

export const useGroupedDetectors = (probe: Probe, allProbes: Probe[]) => {
  const { getSeverityColorByComment } = useSeverityColor();

  return useMemo(() => {
    const map: Record<string, any[]> = {};

    for (const selected of probe.detectors) {
      const detectorType = selected.detector_name;
      const matchingEntries = [];

      for (const p of allProbes) {
        const match = p.detectors.find(d => d.detector_name === detectorType);
        const zscore = match?.zscore;
        const zMissing = zscore == null || isNaN(zscore);

        const color = zMissing
          ? theme.colors.tk150
          : getSeverityColorByComment(match!.zscore_comment);

        const parts = p.probe_name.split(".");
        const label = parts.length > 1 ? parts.slice(1).join(".") : parts[0];

        matchingEntries.push({
          probeName: p.probe_name,
          label,
          zscore: zMissing ? null : zscore,
          detector_score: match?.absolute_score ? match.absolute_score * 100 : null,
          comment: match?.zscore_comment ?? "Unavailable",
          color: p.probe_name === probe.probe_name ? color : theme.colors.tk150,
          unavailable: zMissing,
        });
      }

      if (matchingEntries.length > 0) {
        map[detectorType] = matchingEntries;
      }
    }

    return map;
  }, [probe, allProbes, getSeverityColorByComment]);
};
