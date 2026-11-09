/**
 * @file techniqueIntentRollup.ts
 * @description Builds a renderable view of the technique × intent matrix.
 *              Techniques are ordered worst-first; intents follow code order.
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
  /** 0-1 pass rate, or null when every result was undetermined. */
  score: number | null;
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
  /** 0-1 pass rate, or null when every result was undetermined. */
  score: number | null;
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
  /** Human-readable intent name, without its secondary code. */
  colName: (key: string) => string;
  /** Whether technique rows reuse probe/detector results for the same intent. */
  sharedResults: boolean;
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
      if (!cell || (cell.total_evaluated === 0 && cell.nones === 0)) continue;
      entries.push({
        technique,
        intent,
        techniqueName: summary?.name ?? undefined,
        techniqueDescription: summary?.description ?? undefined,
        intentName: cell.name ?? undefined,
        score: cell.total_evaluated > 0 ? cell.score : null,
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
  /** Name-only chart label; the full label retains its identifying code. */
  otherName?: string;
  /** The underlying matrix cell for this pairing. */
  cell: MatrixCell;
}

/**
 * A primary-axis summary: a technique (with its intents)
 * or an intent (with its techniques). Scored conservatively — the group score
 * is its worst measured child cell, or null when no verdict is available.
 */
export interface AxisGroup {
  /** Active-level primary key (row or column key). */
  key: string;
  /** Display label for the primary key. */
  label: string;
  /** Taxonomy description for the primary key, when known. */
  description?: string;
  /** Worst measured child score, or null when no pairing has a verdict. */
  score: number | null;
  /** Worst-first cross-axis entries. */
  cells: AxisCell[];
}

/**
 * Groups pairings along an axis in the view's order. Within each group, measured
 * pairings are worst-first and undetermined pairings follow. Counts stay on
 * individual cells because contributing probe results can overlap.
 *
 * @param view - A built matrix view
 * @param axis - Which axis to make primary
 */
export function buildAxisGroups(view: MatrixView, axis: TaxonomyAxis): AxisGroup[] {
  const primaries = axis === "technique" ? view.rows : view.cols;
  const secondaries = axis === "technique" ? view.cols : view.rows;
  const primaryLabel = axis === "technique" ? view.rowLabel : view.colName;
  const secondaryLabel = axis === "technique" ? view.colLabel : view.rowLabel;
  const secondaryName = axis === "technique" ? view.colName : view.rowLabel;
  // Both axes now carry a taxonomy description (technique rows, intent columns).
  const primaryDescription = axis === "technique" ? view.rowDescription : view.colDescription;
  const cellOf = (primary: string, secondary: string) =>
    axis === "technique" ? view.cell(primary, secondary) : view.cell(secondary, primary);

  const groups: AxisGroup[] = [];
  for (const primary of primaries) {
    const cells: AxisCell[] = [];
    for (const secondary of secondaries) {
      const cell = cellOf(primary, secondary);
      if (cell)
        cells.push({
          otherKey: secondary,
          otherLabel: secondaryLabel(secondary),
          otherName: secondaryName(secondary),
          cell,
        });
    }
    if (!cells.length) continue;
    cells.sort((a, b) => (a.cell.score ?? 2) - (b.cell.score ?? 2));
    groups.push({
      key: primary,
      label: primaryLabel(primary),
      description: primaryDescription?.(primary),
      score: cells[0].cell.score,
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
  const colName = (key: string) => typologyIntentName(key, typology) ?? intentNames.get(key) ?? key;
  const colLabel = (key: string) => {
    const name = colName(key);
    return name !== key ? `${name} (${key})` : key;
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

  // Technique rank uses its weakest verdict; unscored rows follow scored rows.
  const rowWorst = new Map<string, number>();
  const evidence = new Map<string, string>();
  let sharedResults = false;
  for (const cell of cellMap.values()) {
    rowWorst.set(cell.row, Math.min(rowWorst.get(cell.row) ?? 2, cell.score ?? 2));
    for (const pair of cell.probeDetectorPairs ?? []) {
      const key = JSON.stringify([cell.col, ...pair]);
      const previous = evidence.get(key);
      if (previous !== undefined && previous !== cell.row) sharedResults = true;
      evidence.set(key, cell.row);
    }
  }
  const byWorstThenName = (worst: Map<string, number>) => (a: string, b: string) => {
    const diff = (worst.get(a) ?? 1) - (worst.get(b) ?? 1);
    return diff !== 0 ? diff : a.localeCompare(b);
  };
  const rows = [...rowWorst.keys()].sort(byWorstThenName(rowWorst));
  const cols = [...new Set(entries.map(entry => entry.intent))].sort((a, b) =>
    a.localeCompare(b, "en", { numeric: true })
  );

  return {
    rows,
    cols,
    rowLabel,
    colLabel,
    colName,
    sharedResults,
    rowDescription,
    colDescription,
    cell: (row, col) => cellMap.get(cellKey(row, col)),
  };
}
