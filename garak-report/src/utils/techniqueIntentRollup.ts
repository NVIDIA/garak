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

import type { TaxonomyScoreMap, TechniqueIntentMatrix } from "../types/ReportEntry";
import {
  techniqueGroupKey,
  techniqueGroupLabel,
  intentGroupKey,
  shortenTechnique,
} from "./taxonomyLabels";

/** Roll-up level for the matrix: subcategory/family grouping vs. raw leaves. */
export type MatrixLevel = "grouped" | "leaf";

/** A single underlying technique × intent leaf pair. */
export interface MatrixLeaf {
  technique: string;
  intent: string;
  score: number;
  nEvaluations: number;
  detectors: string[];
}

/** An aggregated (or single-leaf) matrix cell. */
export interface MatrixCell {
  row: string;
  col: string;
  /** Worst (minimum) leaf score — the conservative, security-honest summary. */
  score: number;
  /** Total evaluations pooled into the cell. */
  nEvaluations: number;
  /** Number of leaf pairs pooled into the cell. */
  leafCount: number;
  /** Union of detectors across the pooled leaves. */
  detectors: string[];
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
  cell: (row: string, col: string) => MatrixCell | undefined;
  /** Total leaf pairs across the whole matrix. */
  leafCount: number;
  /** True when grouping actually merges leaves (so a Grouped/Leaf toggle helps). */
  reducible: boolean;
}

/**
 * Rolls a flat taxonomy map up to the heatmap's active level so the 1D
 * breakdown bars share the heatmap's categories. At `leaf` level the map is
 * returned unchanged; at `grouped` level, sibling leaves are pooled by their
 * group key using the same **conservative (worst-leaf) score** the matrix uses,
 * with evaluations summed and probes/detectors unioned. Keeping both views on
 * one aggregation is what makes a bar line up with its heatmap row/column.
 *
 * @param data - Flat technique or intent score map
 * @param kind - Which group-key function to fold by
 * @param level - Target roll-up level
 */
export function rollupTaxonomyMap(
  data: TaxonomyScoreMap,
  kind: "technique" | "intent",
  level: MatrixLevel,
): TaxonomyScoreMap {
  if (level === "leaf") return data;
  const groupKeyOf = kind === "technique" ? techniqueGroupKey : intentGroupKey;
  const rolled: TaxonomyScoreMap = {};
  const uniqueInto = (target: string[], extra?: string[]) => {
    for (const item of extra ?? []) if (!target.includes(item)) target.push(item);
  };
  for (const [key, entry] of Object.entries(data)) {
    const groupKey = groupKeyOf(key);
    const existing = rolled[groupKey];
    if (!existing) {
      rolled[groupKey] = {
        score: entry.score,
        n_evaluations: entry.n_evaluations,
        detectors_used: [...(entry.detectors_used ?? [])],
        aggregation: entry.aggregation,
        probes: [...(entry.probes ?? [])],
      };
    } else {
      existing.score = Math.min(existing.score, entry.score); // conservative: worst leaf
      existing.n_evaluations += entry.n_evaluations;
      uniqueInto(existing.detectors_used, entry.detectors_used);
      uniqueInto(existing.probes!, entry.probes);
    }
  }
  return rolled;
}

/**
 * Drops entries from a flat taxonomy map whose active-level key isn't one of
 * `allowed` (the heatmap's row/column keys). The 1D marginal (`digest.technique`
 * / `digest.intent`) can cover techniques/intents that never co-occur as a
 * technique×intent pair, so it can list more buckets than the matrix has
 * rows/columns; restricting it keeps the bars and heatmap on the same universe.
 *
 * @param data - Flat technique or intent score map (leaf-keyed)
 * @param kind - Which group-key function maps a leaf key to its active-level key
 * @param level - Active roll-up level
 * @param allowed - Active-level keys present in the heatmap (rows or columns)
 */
export function restrictMapToLevelKeys(
  data: TaxonomyScoreMap,
  kind: "technique" | "intent",
  level: MatrixLevel,
  allowed: Set<string>,
): TaxonomyScoreMap {
  const keyOf =
    level === "grouped" ? (kind === "technique" ? techniqueGroupKey : intentGroupKey) : (k: string) => k;
  const restricted: TaxonomyScoreMap = {};
  for (const [key, entry] of Object.entries(data)) {
    if (allowed.has(keyOf(key))) restricted[key] = entry;
  }
  return restricted;
}

const flatten = (matrix: TechniqueIntentMatrix): MatrixLeaf[] => {
  const leaves: MatrixLeaf[] = [];
  for (const technique of Object.keys(matrix)) {
    const row = matrix[technique];
    for (const intent of Object.keys(row)) {
      const entry = row[intent];
      if (!entry) continue;
      leaves.push({
        technique,
        intent,
        score: entry.score,
        nEvaluations: entry.n_evaluations,
        detectors: entry.detectors_used ?? [],
      });
    }
  }
  return leaves;
};

/**
 * Builds a {@link MatrixView} from a raw technique_intent matrix at the given
 * roll-up level.
 */
export function buildMatrixView(matrix: TechniqueIntentMatrix, level: MatrixLevel): MatrixView {
  const leaves = flatten(matrix);

  const rowKeyOf = (l: MatrixLeaf) => (level === "grouped" ? techniqueGroupKey(l.technique) : l.technique);
  const colKeyOf = (l: MatrixLeaf) => (level === "grouped" ? intentGroupKey(l.intent) : l.intent);
  const rowLabel = (key: string) =>
    level === "grouped" ? techniqueGroupLabel(key) : shortenTechnique(key);
  const colLabel = (key: string) => key;

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
        leafCount: 1,
        detectors: [...leaf.detectors],
        leaves: [leaf],
      });
    } else {
      existing.score = Math.min(existing.score, leaf.score); // conservative: worst leaf
      existing.nEvaluations += leaf.nEvaluations;
      existing.leafCount += 1;
      existing.leaves.push(leaf);
      for (const d of leaf.detectors) {
        if (!existing.detectors.includes(d)) existing.detectors.push(d);
      }
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
    cell: (row, col) => cellMap.get(cellKey(row, col)),
    leafCount: leaves.length,
    reducible,
  };
}
