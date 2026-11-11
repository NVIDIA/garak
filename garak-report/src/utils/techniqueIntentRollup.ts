/**
 * @file techniqueIntentRollup.ts
 * @description Builds a renderable view of the technique × intent matrix.
 *              Rows and columns are ordered worst-first so risk surfaces
 *              immediately.
 * @module utils
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type {
  IntentTypology,
  ProbeDetectorPair,
  TechniqueIntentCell,
  TechniqueIntentMatrix,
} from "../types/ReportEntry";
import {
  shortenTechnique,
  intentName as typologyIntentName,
  intentDescription as typologyIntentDescription,
} from "./taxonomyLabels";

/** A single technique × intent pairing from the digest. */
interface MatrixEntry {
  technique: string;
  intent: string;
  /** Human-readable technique name (falls back to the key when absent). */
  techniqueName?: string;
  /** Technique description from the taxonomy, when available. */
  techniqueDescription?: string;
  /** Human-readable intent name (falls back to the code when absent). */
  intentName?: string;
  /** 0-1 pass rate. Pairings the digest left unevaluated (null) are dropped. */
  score: number;
  nEvaluations: number;
  /** Distinct prompts behind the pairing (`nEvaluations` is prompts × detectors). 0 on older reports. */
  nAttempts: number;
  passed: number;
  /** Undetermined evaluations (detector returned no verdict). */
  nones: number;
  /** Detectors that scored this pairing. */
  nDetectors: number;
  probeDetectorPairs?: ProbeDetectorPair[];
}

/** A single technique × intent matrix cell. */
export interface MatrixCell {
  row: string;
  col: string;
  /** 0-1 pass rate for this pairing. */
  score: number;
  /** Total evaluations for the pairing. */
  nEvaluations: number;
  /** Distinct prompts for the pairing (0 on older reports). */
  nAttempts: number;
  /** Passing evaluations. */
  passed: number;
  /** Undetermined evaluations. */
  nones: number;
  /** Detectors that scored the pairing. */
  nDetectors: number;
  /** Contributing probe/detector combinations on newer reports. */
  probeDetectorPairs?: ProbeDetectorPair[];
}

/** A fully built, renderable matrix. */
export interface MatrixView {
  rows: string[];
  cols: string[];
  rowLabel: (key: string) => string;
  colLabel: (key: string) => string;
  /** Technique description for a row key, when the taxonomy provides one. */
  rowDescription: (key: string) => string | undefined;
  /** Intent description for a column key, when known. */
  colDescription: (key: string) => string | undefined;
  cell: (row: string, col: string) => MatrixCell | undefined;
}

const flatten = (matrix: TechniqueIntentMatrix): MatrixEntry[] => {
  const entries: MatrixEntry[] = [];
  for (const technique of Object.keys(matrix)) {
    const row = matrix[technique];
    const summary = row._summary;
    for (const intent of Object.keys(row)) {
      if (intent === "_summary") continue; // reserved per-row summary, not a cell
      const cell = row[intent] as TechniqueIntentCell | undefined;
      // A null score (or nothing evaluated) means this pairing was never probed —
      // drop it so it can't land in the severity bands or worst-first ordering.
      if (!cell || cell.score == null || cell.total_evaluated === 0) continue;
      entries.push({
        technique,
        intent,
        techniqueName: summary?.name ?? undefined,
        techniqueDescription: summary?.description ?? undefined,
        intentName: cell.name ?? undefined,
        score: cell.score,
        nEvaluations: cell.total_evaluated,
        nAttempts: cell.n_attempts ?? 0,
        passed: cell.passed,
        nones: cell.nones,
        nDetectors: cell.probe_detector_pairs
          ? new Set(cell.probe_detector_pairs.map(([, detector]) => detector)).size
          : (cell.n_detectors ?? 0),
        probeDetectorPairs: cell.probe_detector_pairs,
      });
    }
  }
  return entries;
};

/** Technique and intent axes. */
export type TaxonomyAxis = "technique" | "intent";

/** One nested (cross-axis) entry under an {@link AxisGroup}. */
export interface AxisCell {
  /** Cross-axis key (the intent under a technique, or technique under an intent). */
  otherKey: string;
  /** Display label for the cross-axis key. */
  otherLabel: string;
  /** The underlying matrix cell for this pairing. */
  cell: MatrixCell;
}

/**
 * A primary-axis summary: a technique (with its intents)
 * or an intent (with its techniques). Scored conservatively — the group score
 * is its worst child cell — to stay consistent with the heatmap.
 */
export interface AxisGroup {
  /** Active-level primary key (row or column key). */
  key: string;
  /** Display label for the primary key. */
  label: string;
  /** Taxonomy description for the primary key, when known. */
  description?: string;
  /** Worst (minimum) child-cell score — the conservative summary. */
  score: number;
  /** Total evaluations pooled across the group's cells. */
  nEvaluations: number;
  /** Total distinct prompts pooled across the group's cells (0 on older reports). */
  nAttempts: number;
  /** Worst-first cross-axis entries. */
  cells: AxisCell[];
}

/**
 * Reshapes a {@link MatrixView} into worst-first {@link AxisGroup}s for the
 * axis summaries. With `axis="technique"` each group is a technique row and its
 * cells are the intents it was probed against; with `axis="intent"` the roles
 * swap. The primary order follows the view's own worst-first axis ordering, and
 * each group's cells are sorted worst-first, so the most-vulnerable items surface
 * first in both dimensions.
 *
 * @param view - A built matrix view
 * @param axis - Which axis to make primary
 */
export function buildAxisGroups(view: MatrixView, axis: TaxonomyAxis): AxisGroup[] {
  const primaries = axis === "technique" ? view.rows : view.cols;
  const secondaries = axis === "technique" ? view.cols : view.rows;
  const primaryLabel = axis === "technique" ? view.rowLabel : view.colLabel;
  const secondaryLabel = axis === "technique" ? view.colLabel : view.rowLabel;
  // Both axes now carry a taxonomy description (technique rows, intent columns).
  const primaryDescription = axis === "technique" ? view.rowDescription : view.colDescription;
  const cellOf = (primary: string, secondary: string) =>
    axis === "technique" ? view.cell(primary, secondary) : view.cell(secondary, primary);

  const groups: AxisGroup[] = [];
  for (const primary of primaries) {
    const cells: AxisCell[] = [];
    for (const secondary of secondaries) {
      const cell = cellOf(primary, secondary);
      if (cell) cells.push({ otherKey: secondary, otherLabel: secondaryLabel(secondary), cell });
    }
    if (!cells.length) continue;
    cells.sort((a, b) => a.cell.score - b.cell.score);
    groups.push({
      key: primary,
      label: primaryLabel(primary),
      description: primaryDescription?.(primary),
      score: Math.min(...cells.map(c => c.cell.score)),
      nEvaluations: cells.reduce((sum, c) => sum + c.cell.nEvaluations, 0),
      nAttempts: cells.reduce((sum, c) => sum + c.cell.nAttempts, 0),
      cells,
    });
  }
  return groups;
}

/**
 * Builds a {@link MatrixView} from a raw technique_intent matrix.
 */
export function buildMatrixView(
  matrix: TechniqueIntentMatrix,
  typology?: IntentTypology
): MatrixView {
  const entries = flatten(matrix);

  // Prefer digest-supplied taxonomy labels while retaining matrix metadata and
  // raw keys as fallbacks for older reports and unknown codes.
  const techniqueNames = new Map<string, string>();
  const techniqueDescriptions = new Map<string, string>();
  const intentNames = new Map<string, string>();
  for (const entry of entries) {
    if (entry.techniqueName) techniqueNames.set(entry.technique, entry.techniqueName);
    if (entry.techniqueDescription) {
      techniqueDescriptions.set(entry.technique, entry.techniqueDescription);
    }
    if (entry.intentName) intentNames.set(entry.intent, entry.intentName);
  }
  const rowLabel = (key: string) => techniqueNames.get(key) ?? shortenTechnique(key);
  // Intent columns keep their taxonomy code visible alongside the name
  // ("C006 - Anthropomorphise") so the slug is unambiguous; codes with no known
  // name fall back to the bare code.
  const colLabel = (key: string) => {
    const name = typologyIntentName(key, typology) ?? intentNames.get(key);
    return name ? `${key} - ${name}` : key;
  };
  const rowDescription = (key: string) => techniqueDescriptions.get(key);
  const colDescription = (key: string) => typologyIntentDescription(key, typology);

  // Index each pairing by "row\u0000col".
  const cellMap = new Map<string, MatrixCell>();
  const cellKey = (row: string, col: string) => `${row}\u0000${col}`;
  for (const entry of entries) {
    cellMap.set(cellKey(entry.technique, entry.intent), {
      row: entry.technique,
      col: entry.intent,
      score: entry.score,
      nEvaluations: entry.nEvaluations,
      nAttempts: entry.nAttempts,
      passed: entry.passed,
      nones: entry.nones,
      nDetectors: entry.nDetectors,
      probeDetectorPairs: entry.probeDetectorPairs,
    });
  }

  // Worst-first ordering for axes: a row/column's rank is its worst cell.
  const rowWorst = new Map<string, number>();
  const colWorst = new Map<string, number>();
  for (const cell of cellMap.values()) {
    rowWorst.set(cell.row, Math.min(rowWorst.get(cell.row) ?? 1, cell.score));
    colWorst.set(cell.col, Math.min(colWorst.get(cell.col) ?? 1, cell.score));
  }
  const byWorstThenName = (worst: Map<string, number>) => (a: string, b: string) => {
    const diff = (worst.get(a) ?? 1) - (worst.get(b) ?? 1);
    return diff !== 0 ? diff : a.localeCompare(b);
  };
  const rows = [...rowWorst.keys()].sort(byWorstThenName(rowWorst));
  const cols = [...colWorst.keys()].sort(byWorstThenName(colWorst));

  return {
    rows,
    cols,
    rowLabel,
    colLabel,
    rowDescription,
    colDescription,
    cell: (row, col) => cellMap.get(cellKey(row, col)),
  };
}
