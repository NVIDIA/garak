/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { HeatmapCell } from "../types/TechniqueIntentHeatmap";
import type { HeatmapLayout } from "./techniqueIntentHeatmapLayout";

/** Anchor previews to their tile, allowing space above the chart when necessary. */
export const heatmapTooltipPosition =
  ({ left, firstCol, columnWidth, top, rowHeight }: HeatmapLayout) =>
  (
    point: number[],
    params: unknown,
    _dom: HTMLElement,
    rect: { x: number; y: number; width: number; height: number } | null,
    size: { contentSize: number[]; viewSize: number[] }
  ) => {
    const [tooltipWidth, tooltipHeight] = size.contentSize;
    const [viewWidth, viewHeight] = size.viewSize;
    const data = (params as { data?: HeatmapCell }).data;
    const cell = data
      ? {
          x: left + (data.value[0] - firstCol) * columnWidth,
          y: top + data.value[1] * rowHeight,
          width: columnWidth,
          height: rowHeight,
        }
      : (rect ?? { x: point[0], y: point[1], width: 0, height: 0 });
    const bounds = _dom.parentElement?.getBoundingClientRect();
    const visibleTop = bounds ? 8 - bounds.top : 0;
    const visibleBottom = bounds ? window.innerHeight - bounds.top - 8 : viewHeight;
    const gap = 12;
    const clamp = (value: number, max: number) => Math.max(0, Math.min(value, max));
    const clampY = (y: number) => Math.max(visibleTop, Math.min(y, visibleBottom - tooltipHeight));
    // Anchor to the cell instead of following tiny movements inside it.
    if (cell.x + cell.width + gap + tooltipWidth <= viewWidth) {
      return [cell.x + cell.width + gap, clampY(cell.y)];
    }
    if (cell.x - gap - tooltipWidth >= 0) {
      return [cell.x - gap - tooltipWidth, clampY(cell.y)];
    }
    const x = clamp(cell.x + cell.width / 2 - tooltipWidth / 2, viewWidth - tooltipWidth);
    return [
      x,
      cell.y - visibleTop >= tooltipHeight + gap
        ? cell.y - tooltipHeight - gap
        : clampY(cell.y + cell.height + gap),
    ];
  };
