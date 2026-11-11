/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** One keyboard focus stop navigates cells and the top/left taxonomy headers. */
import { useId, useMemo, useState, type FocusEvent, type KeyboardEvent } from "react";
import type { MatrixView } from "../utils/techniqueIntentRollup";
import type { HeatmapCursor, HeatmapSelection } from "../types/TechniqueIntentHeatmap";
import { cursorSelection } from "../utils/techniqueIntentHeatmapSelection";

export function useTechniqueIntentHeatmapKeyboard(
  view: MatrixView,
  onSelect: (selection: HeatmapSelection | null) => void,
  showColumn: (index: number) => void
) {
  const id = useId();
  const [position, setPosition] = useState<HeatmapCursor>({ row: 0, col: 0 });
  const [focused, setFocused] = useState(false);
  const cursor = {
    row: Math.max(-1, Math.min(position.row, view.rows.length - 1)),
    col: Math.max(-1, Math.min(position.col, view.cols.length - 1)),
  };
  const target = useMemo(
    () => cursorSelection({ row: cursor.row, col: cursor.col }, view),
    [view, cursor.row, cursor.col]
  );
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    setFocused(true);
    if (event.key === "Escape") {
      event.preventDefault();
      onSelect(null);
      return;
    }
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (target.axis !== "cell" || view.cell(target.technique, target.intent)) onSelect(target);
      return;
    }
    const next = { ...cursor };
    switch (event.key) {
      case "ArrowUp":
        next.row--;
        break;
      case "ArrowDown":
        next.row++;
        break;
      case "ArrowLeft":
        next.col--;
        break;
      case "ArrowRight":
        next.col++;
        break;
      case "Home":
        next.col = 0;
        break;
      case "End":
        next.col = view.cols.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    next.row = Math.max(-1, Math.min(next.row, view.rows.length - 1));
    next.col = Math.max(-1, Math.min(next.col, view.cols.length - 1));
    if (next.row === -1 && next.col === -1) {
      if (event.key === "ArrowUp") next.col = 0;
      else next.row = 0;
    }
    setPosition(next);
    showColumn(next.col);
  };
  return {
    id,
    cursor,
    target,
    focus: focused ? target : null,
    onKeyDown,
    onFocus: (event: FocusEvent<HTMLDivElement>) =>
      setFocused(event.currentTarget.matches(":focus-visible")),
    onBlur: () => setFocused(false),
  };
}
export type HeatmapKeyboard = ReturnType<typeof useTechniqueIntentHeatmapKeyboard>;
