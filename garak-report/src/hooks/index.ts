/**
 * @file index.ts
 * @description Central barrel export for all custom React hooks.
 * @module hooks
 *
 * @example
 * ```typescript
 * import { useFlattenedModules, useSeverityColor } from '../hooks';
 * ```
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

// Data transformation hooks
export { default as useFlattenedModules } from "./useFlattenedModules";
export { useGroupedDetectors } from "./useGroupedDetectors";
export type { GroupedDetectorEntry, GroupedDetectors } from "./useGroupedDetectors";

// Color and styling hooks
export { default as useSeverityColor } from "./useSeverityColor";
// Note: useSeverityColor.tsx was renamed to useSeverityColor.ts (no JSX)

// Chart hooks
export { useDetectorsChartSeries } from "./useDetectorsChartSeries";
export { useRenderLineItem } from "./useRenderLineItem";
export { useSortedDetectors } from "./useSortedDetectors";

// Tooltip hooks
export { useProbeTooltip } from "./useProbeTooltip";
export { useTooltipFormatter } from "./useTooltipFormatter";

// Utility hooks
export { usePayloadParser } from "./usePayloadParser";
export type { PayloadObject } from "./usePayloadParser";
export { useValueFormatter } from "./useValueFormatter";
export { useZScoreHelpers } from "./useZScoreHelpers";

// Report page hooks
export { useReportData } from "./useReportData";
export type { ReportDataState } from "./useReportData";
export { useModuleFilters } from "./useModuleFilters";
export type { SortOption, ModuleFiltersState } from "./useModuleFilters";
export { useThemeMode } from "./useThemeMode";
export type { ThemeValue, ThemeModeState } from "./useThemeMode";

// Chart options hooks
export { useProbeChartOptions } from "./useProbeChartOptions";
export type { EnrichedProbeData } from "./useProbeChartOptions";
export { useDetectorChartOptions } from "./useDetectorChartOptions";
export type { DetectorChartOptionsResult } from "./useDetectorChartOptions";

