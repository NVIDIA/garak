/**
 * @file types.ts
 * @description Shared types for the technique/intent drill-down interaction.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Coordinated-hover signal shared across the two breakdown bars and the
 * heatmap. Keys are stored in the heatmap's **active-level** space (grouped or
 * leaf), so the heatmap can compare them directly and the flat bars normalize
 * their own key once before comparing. A `null`/empty axis means "not
 * constrained on that axis" (e.g. hovering a technique only constrains rows).
 */
export interface TaxonomyHover {
  /** Active-level technique (row) key, if a technique/row is hovered. */
  technique?: string;
  /** Active-level intent (column) key, if an intent/column is hovered. */
  intent?: string;
}

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
  /**
   * Underlying technique×intent pairs pooled into a grouped cell, worst-first.
   * Present only when a rolled-up cell aggregates more than one leaf, so the
   * drill-down can show exactly what the worst-case score is hiding.
   */
  leaves?: { label: string; score: number; nEvaluations: number }[];
}
