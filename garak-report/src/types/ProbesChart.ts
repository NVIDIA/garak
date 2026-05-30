/**
 * @file ProbesChart.ts
 * @description Type definitions for probe and detector visualization components.
 *              Includes structures for chart data, scores, and DEFCON levels.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Detector result data for a single probe-detector combination.
 * Contains both absolute and relative (z-score) performance metrics.
 */
export type Detector = {
  detector_name: string;
  detector_descr: string;
  absolute_score: number;
  absolute_defcon: number;
  absolute_comment: string;
  relative_score: number;
  relative_defcon: number;
  relative_comment: string;
  detector_defcon: number;
  calibration_used: boolean;
  // New field names (from source)
  total_evaluated?: number;
  passed?: number;
  // Legacy field names (for backward compatibility with old data)
  attempt_count?: number;
  hit_count?: number;
};

/**
 * Probe data structure containing summary statistics and detector results.
 * A probe represents a specific attack technique testing model vulnerabilities.
 */
export type Probe = {
  /** Fully qualified probe name (e.g., "category.subcategory.probe") */
  probe_name: string;
  summary: {
    probe_name: string;
    probe_score: number;
    probe_severity: number;
    probe_descr: string;
    probe_tier: number;
    // New fields
    prompt_count?: number;
    fail_count?: number;
    probe_tags?: string[];
  };
  detectors: Detector[];
};

/**
 * Module (group) containing related probes.
 * Groups probes by vulnerability category for organized display.
 */
export type Module = {
  /** Display name for the module group */
  group_name: string;
  summary: {
    group: string;
    score: number;
    group_defcon: number;
    doc: string;
    group_link: string;
    group_aggregation_function: string;
    unrecognised_aggregation_function: boolean;
    show_top_group_score: boolean;
  };
  probes: Probe[];
};

/** Props for the ProbesChart component */
export type ProbesChartProps = {
  /** Module data containing probes to display */
  module: Module;
  /** Currently selected probe for detail view, or null */
  selectedProbe: Probe | null;
  /** Callback to update probe selection */
  setSelectedProbe: (probe: Probe | null) => void;
};

/**
 * Detector data formatted for ECharts visualization.
 * Extends base detector with display-specific properties.
 */
export type ChartDetector = {
  label: string;
  probeName?: string;
  zscore: number | null;
  detector_score: number | null;
  comment: string | null;
  color: string;
  attempt_count?: number | null;
  hit_count?: number | null;
  unavailable?: boolean;
  detector_defcon?: number | null;
  absolute_defcon?: number | null;
  relative_defcon?: number | null;
};

/**
 * Item style configuration for ECharts series data points.
 */
export interface ChartItemStyle {
  color?: string;
  borderWidth?: number;
  borderColor?: string;
  shadowBlur?: number;
  shadowColor?: string;
}

/**
 * Data point for scatter series (points on lollipop chart).
 */
export interface ChartPointData {
  value: [number, number];
  name: string;
  zscore: number | null;
  detector_score: number | null;
  comment: string | null;
  attempt_count?: number | null;
  hit_count?: number | null;
  itemStyle: ChartItemStyle;
  symbolSize?: number;
}

/**
 * Data point for custom line series (stems on lollipop chart).
 */
export interface ChartLineData {
  value: [number, number, string];
  name: string;
  zscore: number | null;
  detector_score: number | null;
  comment: string | null;
  attempt_count?: number | null;
  hit_count?: number | null;
  itemStyle: ChartItemStyle;
  lineStyle?: {
    width?: number;
    color?: string;
  };
}

/**
 * Series configuration for ECharts scatter points.
 */
export interface ChartPointSeries {
  type: "scatter";
  symbolSize: number;
  data: ChartPointData[];
}

/**
 * Series configuration for ECharts custom lines.
 */
export interface ChartLineSeries {
  type: "custom";
  renderItem: unknown;
  encode: { x: number; y: number };
  data: ChartLineData[];
}

/**
 * Return type for buildSeries function.
 */
export interface ChartSeriesResult {
  pointSeries: ChartPointSeries;
  lineSeries: ChartLineSeries;
  naSeries: { type: "scatter"; data: unknown[] };
  visible: ChartDetector[];
}

/**
 * Enriched probe data with display properties for charts.
 * Extends Probe with computed values for visualization.
 */
export interface EnrichedProbeData extends Probe {
  /** Display label for the probe */
  label: string;
  /** Percentage value for bar chart */
  value: number;
  /** Color for visualization */
  color: string;
  /** Severity level (1-5) */
  severity?: number;
  /** Human-readable severity label */
  severityLabel?: string;
}
