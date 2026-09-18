/**
 * @file taxonomyLabels.test.ts
 * @description Verifies the taxonomy label/path helpers, including the
 *              breadcrumb segments used to show a technique's full taxonomy
 *              path (Issue #1972).
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { describe, expect, it } from "vitest";
import { isTechniqueKey, shortenTechnique, techniquePathSegments } from "../taxonomyLabels";

describe("isTechniqueKey", () => {
  it("recognizes a demon:-prefixed technique key", () => {
    expect(isTechniqueKey("demon:Fictionalizing:Roleplaying:User_persona")).toBe(true);
  });

  it("rejects a flat intent code", () => {
    expect(isTechniqueKey("T009ignore")).toBe(false);
  });
});

describe("techniquePathSegments", () => {
  it("returns every branch from broadest to leaf, stripping the demon: prefix", () => {
    expect(
      techniquePathSegments("demon:Fictionalizing:Roleplaying:User_persona"),
      "full path is preserved, unlike shortenTechnique's last-two truncation"
    ).toEqual(["Fictionalizing", "Roleplaying", "User_persona"]);
  });

  it("handles a single-segment key", () => {
    expect(techniquePathSegments("demon:Base64")).toEqual(["Base64"]);
  });

  it("handles a key with no demon: prefix by treating it as a bare path", () => {
    expect(techniquePathSegments("Encoding:Base64")).toEqual(["Encoding", "Base64"]);
  });
});

describe("shortenTechnique (existing behavior, unchanged)", () => {
  it("keeps only the two most specific segments", () => {
    expect(shortenTechnique("demon:Fictionalizing:Roleplaying:User_persona")).toBe(
      "Roleplaying:User_persona"
    );
  });
});