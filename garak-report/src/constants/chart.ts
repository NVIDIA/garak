/**
 * @file chart.ts
 * @description Chart configuration constants for ECharts visualizations.
 *              Includes dimensions, spacing, symbol sizes, and opacity values.
 * @module constants
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Dimension constants for bar charts, grids, axes, and detector charts */
export const CHART_DIMENSIONS = {
  bar: {
    minHeight: 5,
    maxWidth: 80,
    categoryGap: "30%",
  },
  grid: {
    containLabel: true,
    left: 10,
    right: 20,
    top: 10,
    bottom: 0,
  },
  detectorGrid: {
    containLabel: true,
    left: 10,
    right: 10,
    top: 10,
    bottom: 10,
  },
  axis: {
    fontSize: 14,
    labelRotation: 45,
  },
  zscore: {
    min: -3,
    max: 3,
  },
  detector: {
    minHeight: 200,
    rowHeight: 40,
    extraSpace: 80,
  },
} as const;

/** Default label configuration for chart data points */
export const CHART_LABEL_CONFIG = {
  show: true,
  position: "top" as const,
  fontSize: 12,
} as const;

/** Symbol sizes for normal and selected states in scatter plots */
export const CHART_SYMBOL_SIZES = {
  normal: 10,
  selected: 14,
} as const;

/** Line widths for lollipop chart stems */
export const CHART_LINE_WIDTHS = {
  normal: 2,
  selected: 3,
} as const;

/** Border widths for chart element highlighting */
export const CHART_BORDER_WIDTHS = {
  normal: 0,
  selected: 3,
} as const;

/** Shadow blur values for selected state glow effects */
export const CHART_SHADOW = {
  blur: {
    normal: 0,
    selected: 10,
  },
} as const;

/** Opacity values for full visibility and dimmed (deselected) states */
export const CHART_OPACITY = {
  full: 1,
  dimmed: 0.3,
} as const;
