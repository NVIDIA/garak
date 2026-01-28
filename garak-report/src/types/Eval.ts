/**
 * @file Eval.ts
 * @description Type definitions for the nested evaluation data structure
 *              returned by the Garak backend. These types represent the
 *              hierarchical eval object before flattening.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { Detector, Probe } from "./ProbesChart";
import type { ModuleData } from "./Module";

/**
 * Summary data for a group/module in the eval hierarchy.
 * Matches the structure expected by ModuleData.summary.
 */
export type GroupSummary = ModuleData["summary"];

/**
 * Summary data for a probe in the eval hierarchy.
 * Matches the structure expected by Probe.summary.
 */
export type ProbeSummary = Probe["summary"];

/**
 * Detector data as stored in the eval hierarchy.
 * Extends base Detector with optional fields for raw data.
 */
export type EvalDetectorData = Partial<Detector> & {
  /** Raw absolute score before processing */
  absolute_score?: number;
};

/**
 * Probe entry in the eval hierarchy.
 * Contains a _summary and detector entries keyed by name.
 */
export interface EvalProbe {
  /** Probe summary metadata */
  _summary: ProbeSummary;
  /** Detector entries indexed by detector name */
  [detectorName: string]: ProbeSummary | EvalDetectorData;
}

/**
 * Group entry in the eval hierarchy.
 * Contains a _summary and probe entries keyed by name.
 */
export interface EvalGroup {
  /** Group summary metadata */
  _summary: GroupSummary;
  /** Probe entries indexed by probe name */
  [probeName: string]: GroupSummary | EvalProbe;
}

/**
 * Root eval data structure from the Garak report.
 * Maps group names to their evaluation data.
 */
export type EvalData = Record<string, EvalGroup>;

/**
 * Type guard to check if a value is an EvalGroup.
 * @param value - Value to check
 * @returns True if value is an EvalGroup with _summary
 */
export function isEvalGroup(value: unknown): value is EvalGroup {
  return (
    typeof value === "object" &&
    value !== null &&
    "_summary" in value &&
    typeof (value as EvalGroup)._summary === "object"
  );
}

/**
 * Type guard to check if a value is an EvalProbe.
 * @param value - Value to check
 * @returns True if value is an EvalProbe with _summary
 */
export function isEvalProbe(value: unknown): value is EvalProbe {
  if (typeof value !== "object" || value === null || !("_summary" in value)) {
    return false;
  }
  const summary = (value as EvalProbe)._summary;
  return typeof summary === "object" && summary !== null && "probe_name" in summary;
}

/**
 * Type guard to check if a value is EvalDetectorData.
 * @param value - Value to check
 * @returns True if value looks like detector data
 */
export function isEvalDetectorData(value: unknown): value is EvalDetectorData {
  return (
    typeof value === "object" &&
    value !== null &&
    !("_summary" in value) &&
    ("absolute_score" in value || "detector_name" in value)
  );
}

