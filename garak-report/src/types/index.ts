/**
 * @file index.ts
 * @description Central barrel export for all type definitions.
 *              Import types from this file for clean, consistent imports.
 * @module types
 *
 * @example
 * ```typescript
 * import type { ReportEntry, Probe, Detector, ModuleData } from '../types';
 * ```
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

// Core report types
export type { ReportEntry, CalibrationData, ReportDetailsProps } from "./ReportEntry";

// Eval data types (nested report structure)
export type {
  EvalData,
  EvalGroup,
  EvalProbe,
  EvalDetectorData,
  GroupSummary,
  ProbeSummary,
} from "./Eval";
export { isEvalGroup, isEvalProbe, isEvalDetectorData } from "./Eval";

// Module and probe types
export type { ModuleData } from "./Module";
export type {
  Detector,
  Probe,
  Module,
  ProbesChartProps,
  ChartDetector,
  ChartItemStyle,
  ChartPointData,
  ChartLineData,
  ChartPointSeries,
  ChartLineSeries,
  ChartSeriesResult,
  EnrichedProbeData,
} from "./ProbesChart";

// Detector grouping types
export type { GroupedDetectorEntry, GroupedDetectors } from "./Detector";

// Payload types
export type { PayloadObject } from "./Payload";

// Theme types
export type { ThemeValue } from "./Theme";

// Calibration types
export type { Calibration, CalibrationProps } from "./Calibration";
export type { CalibrationSummaryProps } from "./CalibrationSummary";

// Component props
export type { SetupSectionProps } from "./SetupSection";

// Legacy types (deprecated)
export type { ModuleEntry } from "./ModuleEntry";

// ECharts types
export type {
  EChartsTooltipParams,
  EChartsDetectorData,
  EChartsRenderItemAPI,
} from "./echarts.d";

