/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Describe the active virtual grid cell without duplicating the whole matrix in the DOM. */
import type { MatrixView } from "../../utils/techniqueIntentRollup";
import type { HeatmapGroups } from "../../hooks/useTechniqueIntentHeatmapData";
import type { HeatmapKeyboard } from "../../hooks/useTechniqueIntentHeatmapKeyboard";
import { formatRate } from "../../utils/formatPercentage";
import { DEFCON_LABELS, scoreToDefcon } from "../../constants";

export const HEATMAP_KEYBOARD_HELP =
  "Arrow keys move between cells and the top or left headers. Enter or Space selects or clears the active cell, row or column. Escape clears the selection. Home and End move to the first and last intent.";
const TechniqueIntentHeatmapAccessibility = ({
  view,
  groups,
  keyboard,
  minEvaluations,
}: {
  view: MatrixView;
  groups: HeatmapGroups;
  keyboard: HeatmapKeyboard;
  minEvaluations: number;
}) => {
  const { target, cursor, id } = keyboard;
  const cell = target.axis === "cell" ? view.cell(target.technique, target.intent) : undefined;
  const group = target.axis !== "cell" ? groups[target.axis].get(target.key) : undefined;
  const name =
    target.axis === "cell"
      ? `${view.rowLabel(target.technique)} × ${view.colLabel(target.intent)}`
      : group?.label;
  const score = cell?.score ?? group?.score;
  const result =
    score == null
      ? "Not evaluated"
      : `${formatRate(score)} ${group ? "worst pairing " : ""}pass rate. DC-${scoreToDefcon(score)} ${DEFCON_LABELS[scoreToDefcon(score)]}.`;
  return (
    <div className="sr-only">
      <p id={`${id}-help`}>{HEATMAP_KEYBOARD_HELP}</p>
      <div role="row" aria-rowindex={cursor.row + 2}>
        <span
          id={`${id}-active`}
          aria-colindex={cursor.col + 2}
          role={cursor.row < 0 ? "columnheader" : cursor.col < 0 ? "rowheader" : "gridcell"}
        >
          {name}. {result}
          {cell &&
            ` ${cell.nEvaluations - cell.passed} failed of ${cell.nEvaluations} detector evaluations.${cell.nEvaluations < minEvaluations ? ` Low evaluation count: fewer than ${minEvaluations}.` : ""}`}
        </span>
      </div>
    </div>
  );
};
export default TechniqueIntentHeatmapAccessibility;
