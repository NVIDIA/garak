/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Element-bound measurement and an optional zoom window; undefined means overview. */
import { useCallback, useState } from "react";
import type { MatrixView } from "../utils/techniqueIntentRollup";
import type { HeatmapWindow } from "../types/TechniqueIntentHeatmap";

export function useTechniqueIntentHeatmapNavigation(view: MatrixView) {
  const [width, setWidth] = useState(1200);
  const [matrixWindow, setWindow] = useState<HeatmapWindow>({});
  const measure = useCallback((node: HTMLDivElement | null) => {
    if (!node) return;
    const observer = new ResizeObserver(entries => {
      const next = entries[0]?.contentRect.width;
      if (next > 0) setWidth(next);
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  const zoom = (direction: "in" | "out", count: number) =>
    setWindow(current => ({
      ...current,
      colSpan:
        direction === "in"
          ? Math.max(1, Math.ceil(count / 2))
          : Math.min(view.cols.length, count * 2),
    }));
  const showColumn = (index: number) => {
    if (index < 0) return;
    const count = Math.min(view.cols.length, matrixWindow.colSpan ?? view.cols.length);
    const start = Math.max(0, Math.min(matrixWindow.colStart ?? 0, view.cols.length - count));
    if (index < start || index >= start + count)
      setWindow(current => ({ ...current, colStart: index < start ? index : index - count + 1 }));
  };
  return { width, matrixWindow, measure, zoom, showColumn, setWindow, reset: () => setWindow({}) };
}
export type HeatmapNavigation = ReturnType<typeof useTechniqueIntentHeatmapNavigation>;
