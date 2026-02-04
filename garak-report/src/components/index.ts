/**
 * @file index.ts
 * @description Central barrel export for all components.
 * @module components
 *
 * @example
 * ```typescript
 * import { Header, Footer, ProbesChart, DefconBadge } from '../components';
 * ```
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

// Layout components
export { default as Header } from "./Header";
export { default as Footer } from "./Footer";

// Report components
export { default as ReportDetails } from "./ReportDetails";
export { default as ReportFilterBar } from "./ReportFilterBar";
export { default as ModuleAccordion } from "./ModuleAccordion";
export { default as SummaryStatsCard } from "./SummaryStatsCard";
export { default as DefconSummaryPanel } from "./DefconSummaryPanel";

// Chart components
export { default as ProbesChart } from "./ProbesChart";
export { default as DetectorsView } from "./DetectorsView";

// Subcomponent exports
export { ProbeChartHeader, ProbeTagsList, ProbeBarChart } from "./ProbeChart";
export { DetectorChartHeader, DetectorFilters, DetectorLollipopChart } from "./DetectorChart";

// UI components
export { default as DefconBadge } from "./DefconBadge";
export { default as ColorLegend } from "./ColorLegend";
export { default as ErrorBoundary } from "./ErrorBoundary";

// Display components
export { default as GarakLogo } from "./GarakLogo";
export { default as CalibrationSummary } from "./CalibrationSummary";
export { default as SetupSection } from "./SetupSection";
export { default as MetadataSection } from "./MetadataSection";

