/**
 * @file types.ts
 * @description Shared types for the technique/intent drill-down interaction.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Normalized detail for a selected taxonomy item (a heatmap cell or a
 * technique/intent bar). Drives the drill-down side panel.
 */
export interface TaxonomyDetail {
  /** Origin of the selection: a matrix cell, a technique bar, or an intent bar. */
  kind: "cell" | "technique" | "intent";
  /** Primary heading (technique breadcrumb, or intent code). */
  title: string;
  /** Secondary line (e.g. the intent for a cell, or the axis label). */
  subtitle?: string;
  /** Pass rate, 0-1 (higher is safer). */
  score: number;
  /** Number of evaluations behind this score. */
  nEvaluations: number;
  /** Detectors that contributed to this score. */
  detectors: string[];
  /** Probes that contributed (present on technique/intent buckets, not cells). */
  probes?: string[];
}
