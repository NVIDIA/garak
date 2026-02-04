/**
 * @file Module.ts
 * @description Type definition for flattened module data structure.
 *              Used after transforming nested report data for rendering.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { Probe } from "./ProbesChart";

/**
 * Flattened module data for rendering in the UI.
 * Created by useFlattenedModules hook from nested report structure.
 */
export type ModuleData = {
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
