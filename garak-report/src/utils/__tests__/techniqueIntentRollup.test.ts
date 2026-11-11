/**
 * @file techniqueIntentRollup.test.ts
 * @description Verifies the leaf-level technique × intent matrix view.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { describe, expect, it } from "vitest";
import { buildAxisGroups, buildMatrixView } from "../techniqueIntentRollup";
import { intentDescription, intentName } from "../taxonomyLabels";
import type {
  IntentTypology,
  ProbeDetectorPair,
  TechniqueIntentMatrix,
} from "../../types/ReportEntry";

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

  it("retains provenance and counts unique detectors rather than probe/detector pairs", () => {
    const pairs: ProbeDetectorPair[] = [
      ["grandma.Win10", "always.Fail"],
      ["grandma.Win10", "always.Pass"],
      ["grandma.Win11", "always.Fail"],
    ];
    const view = buildMatrixView({
      t: {
        i: { score: 0.5, passed: 3, total_evaluated: 6, nones: 0, probe_detector_pairs: pairs },
      },
    });
    const cell = view.cell("t", "i");
    expect(cell?.nDetectors, "two probes share a detector").toBe(2);
    expect(cell?.probeDetectorPairs, "pairing provenance is preserved exactly").toEqual(pairs);
    for (const axis of ["technique", "intent"] as const) {
      expect(
        buildAxisGroups(view, axis)[0].cells[0].cell,
        "axis details retain the same provenance"
      ).toBe(cell);
    }
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
