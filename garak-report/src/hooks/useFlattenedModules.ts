/**
 * @file useFlattenedModules.ts
 * @description Hook to transform nested Garak report data into a flat array
 *              structure suitable for UI rendering and filtering.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import type { ReportEntry } from "../types/ReportEntry";
import type { ModuleData } from "../types/Module";
import type { Detector } from "../types/ProbesChart";
import {
  isEvalGroup,
  isEvalProbe,
  isEvalDetectorData,
  type GroupSummary,
  type EvalGroup,
  type EvalProbe,
  type EvalDetectorData,
} from "../types/Eval";

/**
 * Type guard to check if setup has the expected structure.
 * @param setup - Value to check
 * @returns True if setup is a valid config object
 */
function isSetupConfig(setup: unknown): setup is Record<string, unknown> {
  return typeof setup === "object" && setup !== null;
}

/**
 * Creates a complete Detector object from partial eval data.
 * @param name - Detector name
 * @param data - Partial detector data from eval
 * @returns Complete Detector or null if data is insufficient
 */
function buildDetector(name: string, data: EvalDetectorData): Detector | null {
  if (data.absolute_score == null) return null;

  return {
    detector_name: name,
    detector_descr: data.detector_descr ?? "",
    absolute_score: data.absolute_score,
    absolute_defcon: data.absolute_defcon ?? 5,
    absolute_comment: data.absolute_comment ?? "",
    relative_score: data.relative_score ?? 0,
    relative_defcon: data.relative_defcon ?? 5,
    relative_comment: data.relative_comment ?? "",
    detector_defcon: data.detector_defcon ?? 5,
    calibration_used: data.calibration_used ?? false,
    // Pass through backend values directly - no calculations
    total_evaluated: data.total_evaluated ?? data.attempt_count,
    hit_count: data.hit_count,  // Failures count (if provided)
    passed: data.passed,  // Passes count (backend provides this)
    attempt_count: data.attempt_count,  // Preserve original field
  };
}

/**
 * Transforms hierarchical eval data into a flat array structure for rendering.
 *
 * The backend previously provided this flattened structure, but now we compute it
 * client-side to maintain flexibility and reduce backend complexity. This hook
 * handles filtering based on score thresholds and configuration flags.
 *
 * @param report - The raw report data from backend containing nested eval structure
 * @returns Flattened array of modules with their probes and detectors
 *
 * @example
 * ```tsx
 * const modules = useFlattenedModules(selectedReport);
 * // Returns: [{ group_name: "category.probe", summary: {...}, probes: [...] }]
 * ```
 */
export default function useFlattenedModules(report: ReportEntry | null): ModuleData[] {
  return useMemo(() => {
    if (!report) return [];

    // Helper flags from config – fall back to sensible defaults if missing
    const setup = report.meta?.setup;
    const show100Pass = isSetupConfig(setup)
      ? Boolean(setup["reporting.show_100_pass_modules"] ?? false)
      : false;
    const showTopGroupScore = isSetupConfig(setup)
      ? Boolean(setup["reporting.show_top_group_score"] ?? true)
      : true;

    const aggregationUnknown = Boolean(report.meta?.aggregation_unknown);

    const flat: ModuleData[] = [];

    // Iterate through groups in eval
    Object.entries(report.eval ?? {}).forEach(([groupName, groupData]) => {
      if (!isEvalGroup(groupData)) return;

      const evalGroup: EvalGroup = groupData;
      const groupSummary: GroupSummary = {
        ...evalGroup._summary,
        unrecognised_aggregation_function: aggregationUnknown,
        show_top_group_score: showTopGroupScore,
      };

      // Decide if this group should be shown
      /* istanbul ignore else */
      if (groupSummary.score < 1 || show100Pass) {
        const groupObj: ModuleData = {
          group_name: groupName,
          summary: groupSummary,
          probes: [],
        };

        // Process probes within the group
        Object.entries(evalGroup).forEach(([probeName, probeData]) => {
          if (probeName === "_summary") return;
          if (!isEvalProbe(probeData)) return;

          const evalProbe: EvalProbe = probeData;
          const probeSummary = evalProbe._summary;

          const probeEntry: ModuleData["probes"][number] = {
            probe_name: probeName,
            summary: probeSummary,
            detectors: [],
          };

          // Process detectors within the probe
          Object.entries(evalProbe).forEach(([detectorName, detectorData]) => {
            if (detectorName === "_summary") return;
            if (!isEvalDetectorData(detectorData)) return;

            const detector = buildDetector(detectorName, detectorData);
            if (detector && (detector.absolute_score < 1 || show100Pass)) {
              probeEntry.detectors.push(detector);
            }
          });

          groupObj.probes.push(probeEntry);
        });

        flat.push(groupObj);
      }
    });

    return flat;
  }, [report]);
}
