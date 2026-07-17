/**
 * @file techniqueIntentRollup.ts
 * @description Builds a renderable view of the technique × intent matrix at a
 *              chosen roll-up level. Grouped cells aggregate their leaf pairs
 *              **conservatively** — the cell score is the worst (minimum) leaf
 *              score, never a volume-weighted average — so a rolled-up cell can
 *              never appear safer than its most-vulnerable child. Rows and
 *              columns are ordered worst-first so risk surfaces top-left.
 * @module utils
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type {
  IntentTypology,
  TechniqueIntentCell,
  TechniqueIntentMatrix,
} from "../types/ReportEntry";
import {
  techniqueGroupKey,
  techniqueGroupLabel,
  intentGroupKey,
  shortenTechnique,
  intentName as typologyIntentName,
  intentDescription as typologyIntentDescription,
} from "./taxonomyLabels";

/** Roll-up level for the matrix: subcategory/family grouping vs. raw leaves. */
export type MatrixLevel = "grouped" | "leaf";

/** A single underlying technique × intent leaf pair. */
export interface MatrixLeaf {
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
  /** Detectors that scored this pairing (a count; the digest carries no names). */
  nDetectors: number;
}

/** An aggregated (or single-leaf) matrix cell. */
export interface MatrixCell {
  row: string;
  col: string;
  /** Worst (minimum) leaf score — the conservative, security-honest summary. */
  score: number;
  /** Total evaluations pooled into the cell. */
  nEvaluations: number;
  /** Distinct prompts pooled into the cell (0 on older reports). */
  nAttempts: number;
  /** Passing evaluations pooled into the cell. */
  passed: number;
  /** Undetermined evaluations pooled into the cell. */
  nones: number;
  /** Most detectors any pooled leaf was scored by. */
  nDetectors: number;
  /** Number of leaf pairs pooled into the cell. */
  leafCount: number;
  /** The underlying leaf pairs (worst-first). */
  leaves: MatrixLeaf[];
}

/** A fully built, renderable matrix at one roll-up level. */
export interface MatrixView {
  level: MatrixLevel;
  rows: string[];
  cols: string[];
  rowLabel: (key: string) => string;
  colLabel: (key: string) => string;
  /** Technique description for a row key, when the taxonomy provides one. */
  rowDescription: (key: string) => string | undefined;
  /** Intent description for a column key (leaf intent or hazard family), when known. */
  colDescription: (key: string) => string | undefined;
  cell: (row: string, col: string) => MatrixCell | undefined;
  /** Total leaf pairs across the whole matrix. */
  leafCount: number;
  /** True when grouping actually merges leaves (so a Grouped/Leaf toggle helps). */
  reducible: boolean;
}

const flatten = (matrix: TechniqueIntentMatrix): MatrixLeaf[] => {
  const leaves: MatrixLeaf[] = [];
  for (const technique of Object.keys(matrix)) {
    const row = matrix[technique];
    const summary = row._summary;
    for (const intent of Object.keys(row)) {
      if (intent === "_summary") continue; // reserved per-row roll-up, not a cell
      const cell = row[intent] as TechniqueIntentCell | undefined;
      // A null score (or nothing evaluated) means this pairing was never probed —
      // drop it so it can't land in the severity bands or worst-first ordering.
      if (!cell || cell.score == null || cell.total_evaluated === 0) continue;
      leaves.push({
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
        nDetectors: cell.n_detectors,
      });
    }
  }
  return leaves;
};

/** Which taxonomy axis a list is organised by (the other axis nests inside). */
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
 * A primary-axis entry for the accordion lists: a technique (with its intents)
 * or an intent (with its techniques). Scored conservatively — the group score
 * is its worst child cell — to stay consistent with the heatmap.
 */
export interface AxisGroup {
  /** Active-level primary key (row or column key). */
  key: string;
  /** Display label for the primary key. */
  label: string;
  /** Taxonomy description for the primary key (technique axis only, when known). */
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
 * accordion lists. With `axis="technique"` each group is a technique row and its
 * cells are the intents it was probed against; with `axis="intent"` the roles
 * swap. The primary order follows the view's own worst-first axis ordering, and
 * each group's cells are sorted worst-first, so the most-vulnerable items surface
 * first in both dimensions.
 *
 * @param view - A built matrix view (leaf or grouped)
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

/** A technique×intent pairing that fails far worse than either axis usually does. */
export interface NotablePairing {
  /** Row (technique) key. */
  rowKey: string;
  /** Column (intent) key. */
  colKey: string;
  /** Display label for the technique. */
  rowLabel: string;
  /** Display label for the intent. */
  colLabel: string;
  /** This pairing's pass rate (0-1). */
  score: number;
  /** Evaluations behind the pairing. */
  nEvaluations: number;
  /** Best pass rate the technique reaches against any intent. */
  rowBest: number;
  /** Best pass rate the intent reaches against any technique. */
  colBest: number;
  /** How far below `min(rowBest, colBest)` this pairing sits (the "surprise"). */
  gap: number;
}

/**
 * Finds **interaction** pairings: cells that score far worse than either their
 * technique or their intent manages elsewhere. These are the only thing a 2D
 * matrix reveals that the two 1D lists can't — a combination that's uniquely
 * dangerous even though the technique is usually fine and the intent is usually
 * resisted. When the matrix is separable (the common case, where the intent
 * drives the score and techniques behave alike), this returns nothing.
 *
 * A pairing is notable when `min(rowBest, colBest) - score >= margin`, i.e. both
 * its row and its column reach a much safer score somewhere else. Single-cell
 * rows/columns can never qualify (there's no "elsewhere" to compare against).
 *
 * @param view - A built matrix view (typically leaf level, for concrete combos)
 * @param opts - `margin` (default 0.5) and `limit` (default 5, worst-surprise first)
 */
export function findNotablePairings(
  view: MatrixView,
  opts?: { margin?: number; limit?: number },
): NotablePairing[] {
  const margin = opts?.margin ?? 0.5;
  const limit = opts?.limit ?? 5;

  const cells: MatrixCell[] = [];
  for (const row of view.rows) {
    for (const col of view.cols) {
      const cell = view.cell(row, col);
      if (cell) cells.push(cell);
    }
  }

  const rowBest = new Map<string, number>();
  const colBest = new Map<string, number>();
  for (const cell of cells) {
    rowBest.set(cell.row, Math.max(rowBest.get(cell.row) ?? 0, cell.score));
    colBest.set(cell.col, Math.max(colBest.get(cell.col) ?? 0, cell.score));
  }

  const notable: NotablePairing[] = [];
  for (const cell of cells) {
    const rb = rowBest.get(cell.row) ?? 0;
    const cb = colBest.get(cell.col) ?? 0;
    const gap = Math.min(rb, cb) - cell.score;
    if (gap >= margin) {
      notable.push({
        rowKey: cell.row,
        colKey: cell.col,
        rowLabel: view.rowLabel(cell.row),
        colLabel: view.colLabel(cell.col),
        score: cell.score,
        nEvaluations: cell.nEvaluations,
        rowBest: rb,
        colBest: cb,
        gap,
      });
    }
  }
  notable.sort((a, b) => b.gap - a.gap);
  return notable.slice(0, limit);
}

/**
 * Builds a {@link MatrixView} from a raw technique_intent matrix at the given
 * roll-up level.
 */
export function buildMatrixView(
  matrix: TechniqueIntentMatrix,
  level: MatrixLevel,
  typology?: IntentTypology,
): MatrixView {
  const leaves = flatten(matrix);

  const rowKeyOf = (l: MatrixLeaf) => (level === "grouped" ? techniqueGroupKey(l.technique) : l.technique);
  const colKeyOf = (l: MatrixLeaf) => (level === "grouped" ? intentGroupKey(l.intent) : l.intent);

  // Technique names/descriptions only resolve at the leaf level, where a key maps
  // to a single technique; grouped technique keys are prefixes spanning many, so
  // they fall back to the formatted key. Intent labels come from the digest's
  // intent typology, which names every level (leaf, family, category), so grouped
  // columns like "C002" read as their taxonomy name rather than a raw code. The
  // matrix cell's own intent name is kept only as a fallback for unknown codes.
  const techniqueNames = new Map<string, string>();
  const techniqueDescriptions = new Map<string, string>();
  const intentNames = new Map<string, string>();
  for (const leaf of leaves) {
    if (leaf.techniqueName) techniqueNames.set(leaf.technique, leaf.techniqueName);
    if (leaf.techniqueDescription) techniqueDescriptions.set(leaf.technique, leaf.techniqueDescription);
    if (leaf.intentName) intentNames.set(leaf.intent, leaf.intentName);
  }
  const rowLabel = (key: string) =>
    level === "grouped" ? techniqueGroupLabel(key) : techniqueNames.get(key) ?? shortenTechnique(key);
  // Intent columns keep their taxonomy code visible alongside the name
  // ("C006 - Anthropomorphise") so the slug is unambiguous; codes with no known
  // name fall back to the bare code.
  const colLabel = (key: string) => {
    const name = typologyIntentName(key, typology) ?? intentNames.get(key);
    return name ? `${key} - ${name}` : key;
  };
  const rowDescription = (key: string) =>
    level === "grouped" ? undefined : techniqueDescriptions.get(key);
  const colDescription = (key: string) => typologyIntentDescription(key, typology);

  // Aggregate leaves into cells keyed by "row\u0000col".
  const cellMap = new Map<string, MatrixCell>();
  const cellKey = (row: string, col: string) => `${row}\u0000${col}`;
  for (const leaf of leaves) {
    const row = rowKeyOf(leaf);
    const col = colKeyOf(leaf);
    const key = cellKey(row, col);
    const existing = cellMap.get(key);
    if (!existing) {
      cellMap.set(key, {
        row,
        col,
        score: leaf.score,
        nEvaluations: leaf.nEvaluations,
        nAttempts: leaf.nAttempts,
        passed: leaf.passed,
        nones: leaf.nones,
        nDetectors: leaf.nDetectors,
        leafCount: 1,
        leaves: [leaf],
      });
    } else {
      existing.score = Math.min(existing.score, leaf.score); // conservative: worst leaf
      existing.nEvaluations += leaf.nEvaluations;
      existing.nAttempts += leaf.nAttempts;
      existing.passed += leaf.passed;
      existing.nones += leaf.nones;
      existing.nDetectors = Math.max(existing.nDetectors, leaf.nDetectors);
      existing.leafCount += 1;
      existing.leaves.push(leaf);
    }
  }

  // Worst pooled leaf first inside each cell.
  for (const cell of cellMap.values()) {
    cell.leaves.sort((a, b) => a.score - b.score);
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

  // Grouping is only worth offering if it actually collapses rows or columns.
  const leafRows = new Set(leaves.map(l => l.technique)).size;
  const leafCols = new Set(leaves.map(l => l.intent)).size;
  const groupRows = new Set(leaves.map(l => techniqueGroupKey(l.technique))).size;
  const groupCols = new Set(leaves.map(l => intentGroupKey(l.intent))).size;
  const reducible = groupRows < leafRows || groupCols < leafCols;

  return {
    level,
    rows,
    cols,
    rowLabel,
    colLabel,
    rowDescription,
    colDescription,
    cell: (row, col) => cellMap.get(cellKey(row, col)),
    leafCount: leaves.length,
    reducible,
  };
}
