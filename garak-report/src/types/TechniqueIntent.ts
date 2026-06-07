/**
 * @file TechniqueIntent.ts
 * @description Type definitions for the technique & intent (T&I) report views.
 *              Mirrors the `technique_intent_matrix` digest field produced by
 *              `garak.analyze.report_digest._compute_technique_intent_matrix`,
 *              keyed on each probe's `demon:*` technique tags.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * A single technique×intent cell: pooled pass/total counts across the probes
 * and detectors that contributed to a (technique, intent) pairing.
 *
 * `score` is `passed / total_evaluated`, or `null` when nothing was evaluated.
 * `nones` (unscoreable outputs) are excluded from `total_evaluated`.
 */
export type TechniqueIntentCell = {
  /** passed / total_evaluated, or null when total_evaluated is 0 */
  score: number | null;
  passed: number;
  total_evaluated: number;
  nones: number;
  n_detectors: number;
};

/**
 * Per-technique summary emitted under the reserved `_summary` key.
 */
export type TechniqueSummary = {
  n_intents: number;
  n_detectors: number;
};

/**
 * One technique row: a `_summary` plus one entry per intent encountered for
 * that technique. Intent keys are arbitrary strings (e.g. "S003"); the
 * `_summary` key is reserved and never an intent.
 */
export type TechniqueRow = {
  _summary: TechniqueSummary;
} & {
  [intent: string]: TechniqueIntentCell | TechniqueSummary;
};

/**
 * The full `technique_intent_matrix` digest field: technique tag → row.
 * Technique keys are `demon:*` MISP-style tags (e.g. "demon:T:Tech").
 */
export type TechniqueIntentMatrix = {
  [technique: string]: TechniqueRow;
};

/**
 * A technique flattened for display: its tag, summary, and resolved cells.
 */
export type Technique = {
  /** Raw technique tag, e.g. "demon:T:Tech" */
  technique_name: string;
  summary: TechniqueSummary;
  /** Intent name → cell, with the `_summary` key removed */
  cells: Record<string, TechniqueIntentCell>;
};

/**
 * An intent flattened across techniques for the intent-centric view.
 */
export type Intent = {
  /** Intent identifier, e.g. "S003" */
  intent_name: string;
  /** Technique tag → cell for this intent */
  cells: Record<string, TechniqueIntentCell>;
  /** Pooled score across all techniques for this intent, or null */
  score: number | null;
  passed: number;
  total_evaluated: number;
  nones: number;
};

/** Props for the TechniquesView component */
export type TechniquesViewProps = {
  matrix: TechniqueIntentMatrix;
  /** Theme mode for chart/table styling */
  isDark?: boolean;
};

/** Props for the IntentsView component */
export type IntentsViewProps = {
  matrix: TechniqueIntentMatrix;
  isDark?: boolean;
};

/** Reserved key inside a technique row that is not an intent. */
export const SUMMARY_KEY = "_summary" as const;
