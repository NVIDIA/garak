/**
 * @file index.ts
 * @description Barrel export for the technique/intent visualization components.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

export { default as TechniqueIntentPanel } from "./TechniqueIntentPanel";
export type { TechniqueIntentPanelProps } from "./TechniqueIntentPanel";
export { default as TechniqueIntentHeatmap } from "./TechniqueIntentHeatmap";
export { default as TaxonomyBreakdownChart } from "./TaxonomyBreakdownChart";
export { default as TechniqueIntentDetailPanel } from "./TechniqueIntentDetailPanel";
export type { TaxonomyDetail } from "./types";
