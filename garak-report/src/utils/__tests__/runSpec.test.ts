/**
 * @file runSpec.test.ts
 * @description Verifies run.spec object rendering into display tokens.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { describe, it, expect } from "vitest";
import { isRunSpecObject, runSpecTokens } from "../runSpec";

describe("isRunSpecObject", () => {
  it("recognises the {include, exclude} object form", () => {
    expect(isRunSpecObject({ include: [], exclude: [] })).toBe(true);
    expect(isRunSpecObject({ include: ["probes.dan"] })).toBe(true);
  });

  it("rejects strings, arrays and unrelated objects", () => {
    expect(isRunSpecObject("probes.dan")).toBe(false);
    expect(isRunSpecObject(["probes.dan"])).toBe(false);
    expect(isRunSpecObject({ foo: 1 })).toBe(false);
    expect(isRunSpecObject(null)).toBe(false);
  });
});

describe("runSpecTokens", () => {
  it("renders plugin paths verbatim and filters as key:value", () => {
    expect(
      runSpecTokens({
        include: ["probes.donotanswer.DiscriminationExclusionToxicityHatefulOffensive", { intent: "all" }],
        exclude: [],
      }),
    ).toEqual([
      "probes.donotanswer.DiscriminationExclusionToxicityHatefulOffensive",
      "intent:all",
    ]);
  });

  it("prefixes excludes with a dash", () => {
    expect(runSpecTokens({ include: ["probes.dan"], exclude: ["probes.dan.DanInTheWild"] })).toEqual([
      "probes.dan",
      "-probes.dan.DanInTheWild",
    ]);
  });

  it("falls back to the implicit probes.* for an empty spec", () => {
    expect(runSpecTokens({ include: [], exclude: [] })).toEqual(["probes.*"]);
    expect(runSpecTokens({})).toEqual(["probes.*"]);
  });
});
