/**
 * @file TechniqueIntentMatrix.tsx
 * @description Heatmap-style grid rendering the technique×intent pass-rate
 *              matrix. Rows are techniques (or intents, when transposed),
 *              columns are the opposite axis; each cell shows the pooled pass
 *              rate. Shared by TechniquesView and IntentsView.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Stack, Flex, Text, Tooltip } from "@kui/react";
import type { TechniqueIntentCell } from "../types/TechniqueIntent";

/**
 * Map a pass rate (0..1, higher = safer) to a DEFCON severity level (1 worst,
 * 5 best) so cells reuse the existing severity palette. Mirrors the bucketing
 * used for probe scores elsewhere in the report.
 */
const scoreToSeverity = (score: number | null): number => {
  if (score == null) return 0; // unevaluated
  if (score >= 0.9) return 5;
  if (score >= 0.7) return 4;
  if (score >= 0.5) return 3;
  if (score >= 0.3) return 2;
  return 1;
};

const formatScore = (score: number | null): string =>
  score == null ? "—" : `${Math.round(score * 100)}%`;

/** Props for the matrix grid. */
export type TechniqueIntentMatrixProps = {
  /** Row labels (e.g. technique tags or intent ids) */
  rowLabels: string[];
  /** Column labels (the opposite axis) */
  colLabels: string[];
  /** cell lookup: cells[rowLabel]?.[colLabel] */
  cells: Record<string, Record<string, TechniqueIntentCell>>;
  /** Color resolver for a severity level (from useSeverityColor) */
  getColor: (severity: number) => string;
  /** Human label for the row axis, shown in the corner cell */
  rowAxisLabel: string;
  /** Human label for the column axis */
  colAxisLabel: string;
};

/**
 * Render a technique×intent pass-rate heatmap. Empty (technique, intent)
 * pairings — where no probe contributed — render as a muted dash.
 */
const TechniqueIntentMatrix = ({
  rowLabels,
  colLabels,
  cells,
  getColor,
  rowAxisLabel,
  colAxisLabel,
}: TechniqueIntentMatrixProps) => {
  if (rowLabels.length === 0 || colLabels.length === 0) {
    return (
      <Text kind="body/regular/md" style={{ color: "var(--color-tk-400)" }}>
        No technique/intent data in this report.
      </Text>
    );
  }

  // CSS grid: one label column + one column per intent.
  const templateColumns = `minmax(7rem, max-content) repeat(${colLabels.length}, minmax(3.5rem, 1fr))`;

  return (
    <Stack gap="density-sm">
      <div
        role="table"
        aria-label={`${rowAxisLabel} by ${colAxisLabel} pass-rate matrix`}
        style={{ display: "grid", gridTemplateColumns: templateColumns, gap: "2px" }}
      >
        {/* Header row */}
        <div role="columnheader" style={{ padding: "4px 8px" }}>
          <Text kind="label/sm" style={{ color: "var(--color-tk-400)" }}>
            {rowAxisLabel} \ {colAxisLabel}
          </Text>
        </div>
        {colLabels.map((col) => (
          <div key={`h-${col}`} role="columnheader" style={{ padding: "4px 8px", textAlign: "center" }}>
            <Text kind="label/sm">{col}</Text>
          </div>
        ))}

        {/* Body rows */}
        {rowLabels.map((row) => (
          <Flex key={`r-${row}`} style={{ display: "contents" }}>
            <div role="rowheader" style={{ padding: "4px 8px", whiteSpace: "nowrap" }}>
              <Text kind="body/regular/sm">{row}</Text>
            </div>
            {colLabels.map((col) => {
              const cell = cells[row]?.[col];
              const score = cell ? cell.score : null;
              const severity = scoreToSeverity(score);
              const bg = cell ? getColor(severity) : "transparent";
              const label = formatScore(score);
              const cellEl = (
                <div
                  role="cell"
                  data-testid={`ti-cell-${row}-${col}`}
                  style={{
                    padding: "6px 8px",
                    textAlign: "center",
                    backgroundColor: bg,
                    borderRadius: "2px",
                    minHeight: "1.75rem",
                    opacity: cell ? 1 : 0.35,
                  }}
                >
                  <Text kind="body/regular/sm">{label}</Text>
                </div>
              );
              if (!cell) {
                return <div key={`c-${row}-${col}`}>{cellEl}</div>;
              }
              return (
                <Tooltip
                  key={`c-${row}-${col}`}
                  content={
                    `${row} × ${col}: ${label} pass rate ` +
                    `(${cell.passed}/${cell.total_evaluated} evaluations` +
                    `${cell.nones ? `, ${cell.nones} unscoreable` : ""}, ` +
                    `${cell.n_detectors} detector${cell.n_detectors === 1 ? "" : "s"})`
                  }
                >
                  {cellEl}
                </Tooltip>
              );
            })}
          </Flex>
        ))}
      </div>
    </Stack>
  );
};

export default TechniqueIntentMatrix;
