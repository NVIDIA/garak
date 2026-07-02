/**
 * @file traitTypology.drift.test.ts
 * @description Guards the bundled trait-typology snapshot against drift from the
 *              canonical garak source. The report UI names intent codes (leaf,
 *              family, category) from a bundled copy so the digest needn't carry
 *              them; this test fails loudly if that copy falls out of sync.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";

const here = path.dirname(fileURLToPath(import.meta.url));
const bundled = path.resolve(here, "../traitTypology.json");
const canonical = path.resolve(here, "../../../../garak/data/cas/trait_typology.json");

describe("bundled trait typology", () => {
  it("matches the canonical garak/data/cas/trait_typology.json", () => {
    const bundledJson = JSON.parse(readFileSync(bundled, "utf-8"));
    const canonicalJson = JSON.parse(readFileSync(canonical, "utf-8"));
    expect(
      bundledJson,
      "src/data/traitTypology.json is stale — re-copy garak/data/cas/trait_typology.json",
    ).toEqual(canonicalJson);
  });
});
