/**
 * @file taxonomyLabels.ts
 * @description Helpers for formatting technique/intent taxonomy keys for display.
 * @module utils
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { IntentTypology } from "../types/ReportEntry";

// Intent names/descriptions come from `digest.intent_typology`, sourced at
// report-build time from garak's (user-override-aware) trait typology. The
// frontend deliberately bundles no copy and no longer build-time-imports the
// canonical file: either would freeze the package default into the JS bundle and
// ignore user data overrides.

/**
 * Human-readable name for an intent code (leaf, family, or category), looked up
 * in the digest-supplied intent typology. Returns undefined for unknown codes or
 * when the report predates `intent_typology`.
 */
export function intentName(code: string, typology?: IntentTypology): string | undefined {
  return typology?.[code]?.name || undefined;
}

/**
 * Description for an intent code from the digest-supplied intent typology. garak
 * already collapses the taxonomy's explicit `descr` / `default_stub` fallback
 * into a single `descr`, so this just trims it. Undefined when the code is
 * unknown or carries no description.
 */
export function intentDescription(code: string, typology?: IntentTypology): string | undefined {
  return typology?.[code]?.descr?.trim() || undefined;
}

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
