/**
 * @file techniqueIntentRollup.test.ts
 * @description Verifies the leaf-level technique × intent matrix view.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { describe, expect, it } from "vitest";
import { buildAxisGroups, buildMatrixView, findNotablePairings } from "../techniqueIntentRollup";
import { intentDescription, intentName } from "../taxonomyLabels";
import type { IntentTypology, TechniqueIntentMatrix } from "../../types/ReportEntry";

const typology: IntentTypology = {
  C001: { name: "Alpha intent", descr: "Alpha intent description" },
};

const matrixOf = (triples: { t: string; i: string; score: number; n?: number }[]) => {
  const matrix: TechniqueIntentMatrix = {};
  for (const { t, i, score, n } of triples) {
    const total = n ?? 100;
    (matrix[t] ??= {})[i] = {
      score,
      passed: Math.round(score * total),
      total_evaluated: total,
      nones: 0,
      n_detectors: 1,
    };
  }
  return matrix;
};

const matrix = matrixOf([
  {
    t: "demon:Fictionalizing:Roleplaying:DAN_and_target_persona",
    i: "T009ignore",
    score: 0.25,
    n: 100,
  },
  {
    t: "demon:Fictionalizing:Roleplaying:User_persona",
    i: "T009ignore",
    score: 0,
    n: 40,
  },
  {
    t: "demon:Fictionalizing:Roleplaying:User_persona",
    i: "S005hate",
    score: 0.5,
    n: 120,
  },
  {
    t: "demon:Language:Code_and_encode:Token",
    i: "S005hate",
    score: 0.99,
    n: 100,
  },
]);

describe("buildMatrixView", () => {
  it("preserves every concrete technique and intent key", () => {
    const view = buildMatrixView(matrix);

    expect(view.rows, "technique rows remain exact digest keys").toEqual([
      "demon:Fictionalizing:Roleplaying:User_persona",
      "demon:Fictionalizing:Roleplaying:DAN_and_target_persona",
      "demon:Language:Code_and_encode:Token",
    ]);
    expect(view.cols, "intent columns remain exact digest keys").toEqual([
      "T009ignore",
      "S005hate",
    ]);
    expect(
      view.cell("demon:Fictionalizing:Roleplaying:User_persona", "T009ignore")?.score,
      "the concrete pairing keeps its own score"
    ).toBe(0);
  });

  it("orders rows and columns by their worst pairing", () => {
    const view = buildMatrixView(matrix);

    expect(view.rows[0], "the technique containing the 0% pairing comes first").toBe(
      "demon:Fictionalizing:Roleplaying:User_persona"
    );
    expect(view.cols[0], "the intent containing the 0% pairing comes first").toBe("T009ignore");
  });

  it("keeps each pairing's counts unchanged", () => {
    const withCounts: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        X: {
          score: 0.4,
          passed: 40,
          total_evaluated: 100,
          nones: 5,
          n_attempts: 20,
          n_detectors: 3,
        },
      },
    };
    const cell = buildMatrixView(withCounts).cell("demon:Cat:Sub:A", "X");

    expect(cell, "the pairing exists").toBeDefined();
    expect(cell?.passed, "passed count is unchanged").toBe(40);
    expect(cell?.nEvaluations, "evaluation count is unchanged").toBe(100);
    expect(cell?.nones, "undetermined count is unchanged").toBe(5);
    expect(cell?.nAttempts, "prompt count is unchanged").toBe(20);
    expect(cell?.nDetectors, "detector count is unchanged").toBe(3);
  });

  it("handles an empty matrix", () => {
    const view = buildMatrixView({});

    expect(view.rows, "empty input has no rows").toHaveLength(0);
    expect(view.cols, "empty input has no columns").toHaveLength(0);
    expect(view.cell("x", "y"), "empty input has no cells").toBeUndefined();
  });

  it("skips the reserved per-row summary", () => {
    const withSummary: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        _summary: { n_intents: 1, n_detectors: 2 },
        X: {
          score: 0.5,
          passed: 50,
          total_evaluated: 100,
          nones: 0,
          n_detectors: 2,
        },
      },
    };
    const view = buildMatrixView(withSummary);

    expect(view.cols, "the summary never becomes an intent column").toEqual(["X"]);
  });

  it("drops pairings that were not evaluated", () => {
    const sparse: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        X: {
          score: null,
          passed: 0,
          total_evaluated: 0,
          nones: 0,
          n_detectors: 0,
        },
        Y: {
          score: 0.4,
          passed: 40,
          total_evaluated: 100,
          nones: 0,
          n_detectors: 1,
        },
      },
    };
    const view = buildMatrixView(sparse);

    expect(view.cols, "only evaluated intents are shown").toEqual(["Y"]);
    expect(view.cell("demon:Cat:Sub:A", "X"), "the unevaluated pairing is absent").toBeUndefined();
  });

  it("names and describes pairings from digest metadata", () => {
    const named: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        _summary: {
          name: "Alpha technique",
          description: "Does alpha things",
          n_intents: 1,
          n_detectors: 1,
        },
        C001: {
          name: "matrix fallback",
          score: 0.5,
          passed: 50,
          total_evaluated: 100,
          nones: 0,
          n_detectors: 1,
        },
      },
    };
    const view = buildMatrixView(named, typology);

    expect(view.rowLabel("demon:Cat:Sub:A"), "technique name comes from its summary").toBe(
      "Alpha technique"
    );
    expect(view.rowDescription("demon:Cat:Sub:A"), "technique description is retained").toBe(
      "Does alpha things"
    );
    expect(view.colLabel("C001"), "intent label includes its code and typology name").toBe(
      `C001 - ${intentName("C001", typology)}`
    );
    expect(view.colDescription("C001"), "intent description comes from the typology").toBe(
      intentDescription("C001", typology)
    );
  });

  it("falls back to the matrix name and then the raw code", () => {
    const unknown: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        Znovel: {
          name: "Digest Only",
          score: 0.5,
          passed: 50,
          total_evaluated: 100,
          nones: 0,
          n_detectors: 1,
        },
        Zbare: {
          score: 0.5,
          passed: 50,
          total_evaluated: 100,
          nones: 0,
          n_detectors: 1,
        },
      },
    };
    const view = buildMatrixView(unknown, typology);

    expect(view.colLabel("Znovel"), "matrix name is the first fallback").toBe(
      "Znovel - Digest Only"
    );
    expect(view.colLabel("Zbare"), "unknown unnamed intent uses its code").toBe("Zbare");
  });
});

describe("buildAxisGroups", () => {
  it("lists a technique's intents worst-first", () => {
    const groups = buildAxisGroups(buildMatrixView(matrix), "technique");
    const userPersona = groups.find(
      entry => entry.key === "demon:Fictionalizing:Roleplaying:User_persona"
    );

    expect(userPersona, "the technique is represented").toBeDefined();
    expect(userPersona?.score, "the technique surfaces its worst pairing").toBe(0);
    expect(
      userPersona?.cells.map(entry => entry.otherKey),
      "intent pairings are sorted worst-first"
    ).toEqual(["T009ignore", "S005hate"]);
    expect(userPersona?.nEvaluations, "evaluation totals span the technique's pairings").toBe(160);
  });

  it("lists an intent's techniques worst-first", () => {
    const groups = buildAxisGroups(buildMatrixView(matrix), "intent");
    const t009 = groups.find(entry => entry.key === "T009ignore");

    expect(t009, "the intent is represented").toBeDefined();
    expect(t009?.score, "the intent surfaces its worst pairing").toBe(0);
    expect(
      t009?.cells.map(entry => entry.otherKey),
      "technique pairings are sorted worst-first"
    ).toEqual([
      "demon:Fictionalizing:Roleplaying:User_persona",
      "demon:Fictionalizing:Roleplaying:DAN_and_target_persona",
    ]);
  });

  it("returns no entries for an empty matrix", () => {
    expect(
      buildAxisGroups(buildMatrixView({}), "technique"),
      "empty input has no axis entries"
    ).toHaveLength(0);
  });
});

describe("findNotablePairings", () => {
  it("flags a combination that fails far worse than its row and column elsewhere", () => {
    const view = buildMatrixView(
      matrixOf([
        { t: "demon:Cat:Sub:A", i: "X", score: 1 },
        { t: "demon:Cat:Sub:A", i: "Y", score: 0 },
        { t: "demon:Cat:Other:B", i: "X", score: 0.95 },
        { t: "demon:Cat:Other:B", i: "Y", score: 0.9 },
      ])
    );
    const notable = findNotablePairings(view);

    expect(notable, "only the uniquely weak A × Y interaction is notable").toHaveLength(1);
    expect(notable[0].rowKey, "the notable technique is A").toBe("demon:Cat:Sub:A");
    expect(notable[0].colKey, "the notable intent is Y").toBe("Y");
    expect(notable[0].gap, "the interaction gap uses both axes' best scores").toBeCloseTo(0.9);
  });

  it("returns nothing for a separable matrix", () => {
    const view = buildMatrixView(
      matrixOf([
        { t: "demon:Cat:Sub:A", i: "X", score: 1 },
        { t: "demon:Cat:Sub:A", i: "Y", score: 0 },
        { t: "demon:Cat:Other:B", i: "X", score: 1 },
        { t: "demon:Cat:Other:B", i: "Y", score: 0 },
      ])
    );

    expect(
      findNotablePairings(view),
      "intent-driven failures are not interaction effects"
    ).toHaveLength(0);
  });

  it("never flags a single-cell row or column", () => {
    const view = buildMatrixView(matrixOf([{ t: "demon:Cat:Sub:A", i: "X", score: 0 }]));

    expect(
      findNotablePairings(view),
      "a pairing needs another result on each axis for comparison"
    ).toHaveLength(0);
  });

  it("orders by surprise and respects the limit", () => {
    const view = buildMatrixView(
      matrixOf([
        { t: "demon:Cat:Sub:A", i: "X", score: 1 },
        { t: "demon:Cat:Sub:A", i: "Y", score: 0.1 },
        { t: "demon:Cat:Other:B", i: "X", score: 1 },
        { t: "demon:Cat:Other:B", i: "Y", score: 0.9 },
        { t: "demon:Cat:Third:C", i: "X", score: 1 },
        { t: "demon:Cat:Third:C", i: "Y", score: 0 },
      ])
    );
    const notable = findNotablePairings(view, { limit: 1 });

    expect(notable, "the result respects the requested limit").toHaveLength(1);
    expect(notable[0].rowKey, "the largest interaction gap comes first").toBe("demon:Cat:Third:C");
  });
});
