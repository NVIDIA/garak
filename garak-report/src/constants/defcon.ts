/**
 * @file defcon.ts
 * @description DEFCON level constants, labels, and risk comment mappings.
 *              DEFCON levels range from 1 (Critical Risk) to 5 (Low Risk).
 * @module constants
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Ordered array of all valid DEFCON levels (1=Critical to 5=Low) */
export const DEFCON_LEVELS = [1, 2, 3, 4, 5] as const;

/** Human-readable labels for each DEFCON level */
export const DEFCON_LABELS = {
  1: "Critical Risk",
  2: "Very High Risk",
  3: "Elevated Risk",
  4: "Medium Risk",
  5: "Low Risk",
  default: "Unknown",
} as const;

/**
 * Risk comment strings used in detector/probe analysis.
 * Maps to DEFCON levels for color coding and severity display.
 */
export const DEFCON_RISK_COMMENTS = {
  critical: "critical risk",
  veryHigh: "very high risk",
  elevated: "elevated risk",
  medium: "medium risk",
  low: "low risk",
  // Legacy fallbacks
  veryPoor: "very poor",
  poor: "poor",
  belowAverage: "below average",
  average: "average",
  aboveAverage: "above average",
  excellent: "excellent",
  competitive: "competitive",
} as const;

/** Type representing valid DEFCON levels (1-5) */
export type DefconLevel = (typeof DEFCON_LEVELS)[number];
