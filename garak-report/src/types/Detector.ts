/**
 * @file Detector.ts
 * @description Type definitions for grouped detector data used in comparison views.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Entry representing a single detector result in the grouped view.
 * Contains display data and metrics for the comparison chart.
 */
export interface GroupedDetectorEntry {
  /** Name of the probe this detector belongs to */
  probeName: string;
  /** Display label for the detector */
  label: string;
  /** Z-score (relative performance), null if unavailable */
  zscore: number | null;
  /** Absolute detector score as percentage, null if unavailable */
  detector_score: number | null;
  /** Performance comment (e.g., "critical risk", "low risk") */
  comment: string;
  /** Total number of evaluations (from source: total_evaluated) */
  total_evaluated: number | null;
  /** Number that passed (from source: passed) */
  passed: number | null;
  /** Color for visualization */
  color: string;
  /** Whether detector data is unavailable */
  unavailable: boolean;
  /** Overall DEFCON level for this detector */
  detector_defcon: number | null;
  /** DEFCON level based on absolute score */
  absolute_defcon: number | null;
  /** DEFCON level based on relative score */
  relative_defcon: number | null;
}

/** Map of detector type names to their grouped entries across probes */
export type GroupedDetectors = Record<string, GroupedDetectorEntry[]>;

