/**
 * @file taxonomyLabels.ts
 * @description Helpers for formatting technique/intent taxonomy keys for display.
 * @module utils
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Shortens a hierarchical `demon:` technique key for axis labels.
 * Strips the `demon:` prefix and keeps the two most specific segments.
 *
 * @example
 * shortenTechnique("demon:Fictionalizing:Roleplaying:User_persona") // "Roleplaying:User_persona"
 */
export function shortenTechnique(key: string): string {
  const stripped = key.replace(/^demon:/, "");
  const segments = stripped.split(":");
  return segments.slice(-2).join(":");
}

/**
 * Formats a technique key as a readable breadcrumb for tooltips.
 *
 * @example
 * formatTechniqueFull("demon:Fictionalizing:Roleplaying:User_persona")
 * // "Fictionalizing › Roleplaying › User_persona"
 */
export function formatTechniqueFull(key: string): string {
  return key.replace(/^demon:/, "").split(":").join(" › ");
}
