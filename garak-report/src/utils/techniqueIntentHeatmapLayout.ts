/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { format } from "echarts";
import type { MatrixView } from "./techniqueIntentRollup";
import type { HeatmapWindow } from "../types/TechniqueIntentHeatmap";

/** Measure full codes and use the smallest non-overlapping label angle. */
export function getHeatmapLayout(
  view: MatrixView,
  width: number,
  { colSpan, colStart = 0 }: HeatmapWindow = {}
) {
  const left = width < 600 ? 144 : 248;
  const colCount = Math.min(view.cols.length, Math.max(1, colSpan ?? view.cols.length));
  const rowCount = view.rows.length;
  const firstCol = Math.max(0, Math.min(colStart, view.cols.length - colCount));
  const right = 48;
  const columnWidth = Math.max(1, width - left - right) / Math.max(1, colCount);
  const compactLabels = columnWidth < 100;
  const rowHeight = Math.max(24, Math.min(44, columnWidth));
  const labelFontSize = 13;
  const labelLineHeight = 18;
  const labelGap = 4;
  const labelFont = `${labelFontSize}px sans-serif`;
  const visibleCodes = view.cols.slice(firstCol, firstCol + colCount);
  const codeRects = compactLabels
    ? visibleCodes.map(key => format.getTextRect(key, labelFont))
    : [];
  const codeHeight = Math.max(labelFontSize, ...codeRects.map(rect => rect.height));
  const longestCode = Math.max(0, ...codeRects.map(rect => rect.width));
  const labelInterval = compactLabels
    ? Math.max(
        0,
        Math.ceil((codeHeight + labelGap) / (columnWidth * Math.sin((85 * Math.PI) / 180))) - 1
      )
    : 0;
  const labelSpacing = columnWidth * (labelInterval + 1);
  const followingCodeWidth = Math.max(0, ...codeRects.slice(1).map(rect => rect.width));
  let labelAngle = 0;
  if (compactLabels && codeRects.length > 1) {
    // Parallel labels separate either along their text or across their height.
    while (labelAngle < 85) {
      const radians = (labelAngle * Math.PI) / 180;
      if (
        followingCodeWidth + labelGap <= labelSpacing * Math.cos(radians) ||
        codeHeight + labelGap <= labelSpacing * Math.sin(radians)
      )
        break;
      labelAngle++;
    }
  }
  const labelWidth = Math.max(80, Math.floor(columnWidth) - 12);
  const labelLines = compactLabels
    ? 0
    : Math.max(
        1,
        ...visibleCodes.map(
          key => 1 + Math.ceil(format.getTextRect(view.colLabel(key), labelFont).width / labelWidth)
        )
      );
  const top = compactLabels
    ? Math.ceil(longestCode * Math.sin((labelAngle * Math.PI) / 180) + codeHeight) + 20
    : labelLines * labelLineHeight + 24;
  const bottom = colCount < view.cols.length ? 48 : 16;

  return {
    left,
    right,
    top,
    bottom,
    firstCol,
    colCount,
    rowCount,
    columnWidth,
    rowHeight,
    compactLabels,
    labelAngle,
    labelWidth,
    labelInterval,
    labelFontSize,
    labelLineHeight,
    height: rowCount * rowHeight + top + bottom,
  };
}
export type HeatmapLayout = ReturnType<typeof getHeatmapLayout>;
