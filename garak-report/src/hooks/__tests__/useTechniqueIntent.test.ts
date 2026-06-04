// src/hooks/__tests__/useTechniqueIntent.test.ts
import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import useTechniqueIntent from "../useTechniqueIntent";
import type { TechniqueIntentMatrix } from "../../types/TechniqueIntent";

const cell = (passed: number, total: number, nones = 0, n_detectors = 1) => ({
  score: total ? passed / total : null,
  passed,
  total_evaluated: total,
  nones,
  n_detectors,
});

const matrix: TechniqueIntentMatrix = {
  "demon:T:Beta": {
    _summary: { n_intents: 2, n_detectors: 2 },
    S003: cell(8, 10, 0, 2),
    S008: cell(2, 4, 1, 1),
  },
  "demon:T:Alpha": {
    _summary: { n_intents: 1, n_detectors: 1 },
    S003: cell(5, 10, 0, 1),
  },
};

describe("useTechniqueIntent", () => {
  it("returns empty collections for missing or empty matrix", () => {
    expect(renderHook(() => useTechniqueIntent(undefined)).result.current).toEqual({
      techniques: [],
      intents: [],
      intentNames: [],
    });
    expect(renderHook(() => useTechniqueIntent({})).result.current.techniques).toHaveLength(0);
  });

  it("flattens techniques sorted by name and strips _summary from cells", () => {
    const { techniques } = renderHook(() => useTechniqueIntent(matrix)).result.current;
    expect(techniques.map((t) => t.technique_name)).toEqual([
      "demon:T:Alpha",
      "demon:T:Beta",
    ]);
    const beta = techniques.find((t) => t.technique_name === "demon:T:Beta")!;
    expect(Object.keys(beta.cells).sort()).toEqual(["S003", "S008"]);
    expect(beta.summary).toEqual({ n_intents: 2, n_detectors: 2 });
    // _summary must never leak into cells
    expect("_summary" in beta.cells).toBe(false);
  });

  it("pools intents across techniques by count, not by averaging scores", () => {
    const { intents, intentNames } = renderHook(() =>
      useTechniqueIntent(matrix)
    ).result.current;
    expect(intentNames).toEqual(["S003", "S008"]);
    const s003 = intents.find((i) => i.intent_name === "S003")!;
    // Beta 8/10 + Alpha 5/10 => 13/20 = 0.65, not (0.8+0.5)/2
    expect(s003.passed).toBe(13);
    expect(s003.total_evaluated).toBe(20);
    expect(s003.score).toBeCloseTo(0.65);
    expect(Object.keys(s003.cells).sort()).toEqual(["demon:T:Alpha", "demon:T:Beta"]);
  });

  it("carries nones through without counting them in totals", () => {
    const { intents } = renderHook(() => useTechniqueIntent(matrix)).result.current;
    const s008 = intents.find((i) => i.intent_name === "S008")!;
    expect(s008.nones).toBe(1);
    expect(s008.total_evaluated).toBe(4);
  });

  it("sets score to null when nothing was evaluated", () => {
    const empty: TechniqueIntentMatrix = {
      "demon:T:X": {
        _summary: { n_intents: 1, n_detectors: 0 },
        S001: cell(0, 0),
      },
    };
    const { intents } = renderHook(() => useTechniqueIntent(empty)).result.current;
    expect(intents[0].score).toBeNull();
  });
});
