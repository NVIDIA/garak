/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { format } from "echarts";
import type { MatrixView } from "./techniqueIntentRollup";
import type { HeatmapWindow } from "../types/TechniqueIntentHeatmap";

/** Measure intent names and use the smallest angle that fits labels and margins. */
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
  const labelTexts = visibleCodes.map(key =>
    view.colName(key) === key ? key : `${view.colName(key)}\n${key}`
  );
  const labelRects = compactLabels
    ? labelTexts.map(text => format.getTextRect(text, labelFont))
    : [];
  const labelHeight = Math.max(
    labelLineHeight,
    ...labelTexts.map(text => text.split("\n").length * labelLineHeight)
  );
  const longestLabel = Math.max(0, ...labelRects.map(rect => rect.width));
  const labelInterval =
    compactLabels && longestLabel + labelGap > columnWidth
      ? Math.max(
          0,
          Math.ceil((labelHeight + labelGap) / (columnWidth * Math.sin((85 * Math.PI) / 180))) - 1
        )
      : 0;
  const labelSpacing = columnWidth * (labelInterval + 1);
  const followingLabelWidth = Math.max(0, ...labelRects.slice(1).map(rect => rect.width));
  let labelAngle = 0;
  if (compactLabels && labelRects.length > 1) {
    // Parallel labels separate either along their text or across their height.
    while (labelAngle < 85) {
      const radians = (labelAngle * Math.PI) / 180;
      if (
        (labelRects[0]?.width ?? 0) * Math.cos(radians) + labelHeight * Math.sin(radians) <=
          left + columnWidth / 2 - 8 &&
        (followingLabelWidth + labelGap <= labelSpacing * Math.cos(radians) ||
          labelHeight + labelGap <= labelSpacing * Math.sin(radians))
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
    ? Math.ceil(longestLabel * Math.sin((labelAngle * Math.PI) / 180) + labelHeight) + 20
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
