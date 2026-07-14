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

/**
 * Roll-up key for a technique: drops the most-specific (leaf) segment so
 * sibling leaves share a row. `demon:Cat:Sub:Leaf` -> `demon:Cat:Sub`.
 * Keys without a leaf segment are returned unchanged.
 */
export function techniqueGroupKey(key: string): string {
  const segments = key.split(":");
  return segments.length > 1 ? segments.slice(0, -1).join(":") : key;
}

/**
 * Readable label for a grouped technique key (subcategory breadcrumb).
 *
 * @example
 * techniqueGroupLabel("demon:Fictionalizing:Roleplaying") // "Fictionalizing › Roleplaying"
 */
export function techniqueGroupLabel(key: string): string {
  return formatTechniqueFull(key);
}

/**
 * Roll-up key for an intent code: its hazard-family prefix so variants share a
 * column. `S004lewd` / `S004erotica` -> `S004`. Codes that don't match the
 * `<letter><3 digits>` pattern are returned unchanged.
 */
export function intentGroupKey(code: string): string {
  const match = code.match(/^[A-Za-z]\d{3}/);
  return match ? match[0] : code;
}
