/**
 * @file ModuleEntry.ts
 * @description Legacy module entry type (string-based scores).
 * @module types
 *
 * @see ModuleData in Module.ts for current implementation
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Legacy module entry format with string scores.
 * @deprecated Use ModuleData from Module.ts instead
 */
export type ModuleEntry = {
  /** Module identifier */
  module: string;
  /** Score as formatted string (e.g., "85%") */
  module_score: string;
  /** Module documentation/description */
  module_doc: string;
  /** Link to module documentation */
  group_link: string;
  /** Severity level (1-5) */
  severity: number;
};
