/**
 * @file runSpec.ts
 * @description Renders a `run.spec` selection value (the unified probe/buff
 *              selection grammar) into readable tokens for the Setup view.
 *              Mirrors the backend `_runspec_to_probespec`: plugin paths render
 *              verbatim, single-key filters (tag/tier/intent) as `key:value`,
 *              and excludes are prefixed with `-`. Handles the structured
 *              `{include, exclude}` object that older digests store un-rendered,
 *              so the spec reads well even without regenerating the report.
 * @module utils
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** A single selector: a plugin path string or a single-key filter mapping. */
type SpecItem = string | Record<string, unknown>;

/** The structured config-form of a run.spec. */
export interface RunSpecObject {
  include?: SpecItem[];
  exclude?: SpecItem[];
}

/** True for the `{include, exclude}` object form of a run.spec. */
export function isRunSpecObject(value: unknown): value is RunSpecObject {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    ("include" in value || "exclude" in value)
  );
}

const specToken = (item: SpecItem): string => {
  if (typeof item === "string") return item;
  const entry = Object.entries(item)[0];
  return entry ? `${entry[0]}:${entry[1]}` : "";
};

/**
 * Flattens a run.spec object into display tokens (includes first, then excludes
 * prefixed with `-`). An empty spec falls back to the implicit `probes.*`.
 */
export function runSpecTokens(spec: RunSpecObject): string[] {
  const tokens = [
    ...(spec.include ?? []).map(specToken),
    ...(spec.exclude ?? []).map(item => `-${specToken(item)}`),
  ].filter(Boolean);
  return tokens.length ? tokens : ["probes.*"];
}
