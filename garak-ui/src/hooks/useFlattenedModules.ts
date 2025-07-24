import { useMemo } from "react";
import type { ReportEntry } from "../types/ReportEntry";
import type { ModuleData } from "../types/Module";

/**
 * Derive the flattened modules array from a report digest.
 * The backend used to include this in `results`; now we compute it client-side.
 */
export default function useFlattenedModules(report: ReportEntry | null): ModuleData[] {
  return useMemo(() => {
    if (!report) return [];

    // Helper flags from config – fall back to sensible defaults if missing
    const setup = report.meta?.setup as Record<string, unknown> | undefined;
    const show100Pass = Boolean(setup?.["reporting.show_100_pass_modules"] ?? false);
    const showTopGroupScore = Boolean(
      setup?.["reporting.show_top_group_score"] ?? true
    );

    const aggregationUnknown = Boolean(report.meta?.aggregation_unknown);

    const flat: ModuleData[] = [];

    // Iterate through groups in eval
    Object.entries(report.eval ?? {}).forEach(([groupName, groupData]) => {
      if (typeof groupData !== "object" || groupData === null) return;

      const groupSummary = {
        ...(groupData as any)["_summary"],
        unrecognised_aggregation_function: aggregationUnknown,
        show_top_group_score: showTopGroupScore,
      } as ModuleData["summary"];

      // Decide if this group should be shown
      /* istanbul ignore else */
      if (groupSummary.score < 1 || show100Pass) {
        const groupObj: ModuleData = {
          group_name: groupName,
          summary: groupSummary,
          probes: [],
        };

        // Probes
        Object.entries(groupData as Record<string, any>).forEach(
          ([probeName, probeData]) => {
            if (probeName === "_summary") return;
            const probeSummary = (probeData as any)["_summary"];
            if (!probeSummary) return;

            const probeObj = {
              probe_name: probeName,
              summary: probeSummary,
              detectors: [] as any[],
            };

            // Detectors
            Object.entries(probeData as Record<string, any>).forEach(
              ([detectorName, detectorData]) => {
                if (detectorName === "_summary") return;
                if (
                  detectorData?.absolute_score < 1 ||
                  show100Pass
                ) {
                  probeObj.detectors.push({
                    detector_name: detectorName,
                    ...detectorData,
                  });
                }
              }
            );

            groupObj.probes.push(probeObj as any);
          }
        );

        flat.push(groupObj);
      }
    });

    return flat;
  }, [report]);
} 