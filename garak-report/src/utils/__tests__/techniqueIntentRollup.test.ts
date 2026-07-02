/**
 * @file techniqueIntentRollup.test.ts
 * @description Verifies the conservative (worst-case) roll-up of the
 *              technique × intent matrix.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { describe, it, expect } from "vitest";
import {
  buildAxisGroups,
  buildMatrixView,
  findNotablePairings,
} from "../techniqueIntentRollup";
import { intentName, intentDescription } from "../taxonomyLabels";
import type { TechniqueIntentMatrix } from "../../types/ReportEntry";

/** Builds a matrix from terse {technique, intent, score} triples for tests. */
const matrixOf = (triples: { t: string; i: string; score: number; n?: number }[]) => {
  const m: TechniqueIntentMatrix = {};
  for (const { t, i, score, n } of triples) {
    const total = n ?? 100;
    (m[t] ??= {})[i] = {
      score,
      passed: Math.round(score * total),
      total_evaluated: total,
      nones: 0,
      n_detectors: 1,
    };
  }
  return m;
};

// Subset of cells that exercises both row grouping (Roleplaying subcategory)
// and worst-case pooling within a grouped cell.
const cells = [
  { t: "demon:Fictionalizing:Roleplaying:DAN_and_target_persona", i: "T009ignore", passed: 650, total: 2580 },
  { t: "demon:Fictionalizing:Roleplaying:User_persona", i: "T009ignore", passed: 0, total: 40 },
  { t: "demon:Fictionalizing:Roleplaying:User_persona", i: "S005hate", passed: 60, total: 120 },
  { t: "demon:Language:Code_and_encode:Data_encoding", i: "S005hate", passed: 27691, total: 27740 },
  { t: "demon:Language:Code_and_encode:Token", i: "S005hate", passed: 1847, total: 1850 },
];

const matrix: TechniqueIntentMatrix = {};
for (const c of cells) {
  (matrix[c.t] ??= {})[c.i] = {
    score: c.passed / c.total,
    passed: c.passed,
    total_evaluated: c.total,
    nones: 0,
    n_detectors: 1,
  };
}

describe("buildMatrixView", () => {
  it("collapses leaves into subcategory rows / intent families", () => {
    const view = buildMatrixView(matrix, "grouped");
    expect(view.rows).toContain("demon:Fictionalizing:Roleplaying");
    expect(view.cols).toContain("T009"); // T009ignore -> T009 family
    expect(view.cols).toContain("S005"); // S005hate -> S005 family
    expect(view.reducible).toBe(true);
  });

  it("colors a grouped cell by its WORST leaf, not a volume-weighted average", () => {
    const view = buildMatrixView(matrix, "grouped");
    const cell = view.cell("demon:Fictionalizing:Roleplaying", "T009");
    expect(cell).toBeDefined();
    // Leaves: 650/2580 (.252) and 0/40 (0). Worst = 0; micro-avg would be ~.248.
    expect(cell!.score).toBe(0);
    expect(cell!.leafCount).toBe(2);
    expect(cell!.nEvaluations).toBe(2620);
    // Worst leaf is listed first for the drill-down.
    expect(cell!.leaves[0].score).toBe(0);
  });

  it("orders rows worst-first", () => {
    const view = buildMatrixView(matrix, "grouped");
    expect(view.rows[0]).toBe("demon:Fictionalizing:Roleplaying"); // contains the 0% cell
  });

  it("leaf level keeps every pair separate", () => {
    const view = buildMatrixView(matrix, "leaf");
    expect(view.rows.length).toBe(4); // 4 distinct technique leaves in the fixture
    const cell = view.cell("demon:Fictionalizing:Roleplaying:User_persona", "T009ignore");
    expect(cell!.leafCount).toBe(1);
    expect(cell!.score).toBe(0);
  });

  it("pools across intent leaves into the same intent family column", () => {
    const view = buildMatrixView(matrix, "grouped");
    // Roleplaying × S005 only has User_persona/S005hate (0.5), single leaf.
    const cell = view.cell("demon:Fictionalizing:Roleplaying", "S005");
    expect(cell).toBeDefined();
    expect(cell!.score).toBe(0.5);
    expect(cell!.leafCount).toBe(1);
  });

  it("sums evaluation counts across pooled leaves", () => {
    const view = buildMatrixView(matrix, "grouped");
    const cell = view.cell("demon:Fictionalizing:Roleplaying", "T009");
    // 2580 (DAN_and_target_persona) + 40 (User_persona) pooled.
    expect(cell!.nEvaluations).toBe(2620);
  });

  it("returns undefined for absent cells without throwing", () => {
    const view = buildMatrixView(matrix, "grouped");
    expect(view.cell("does:not:exist", "T009")).toBeUndefined();
  });

  describe("edge cases", () => {
    it("handles an empty matrix gracefully", () => {
      const view = buildMatrixView({}, "grouped");
      expect(view.rows).toHaveLength(0);
      expect(view.cols).toHaveLength(0);
      expect(view.reducible).toBe(false);
      expect(view.cell("x", "y")).toBeUndefined();
    });

    it("is not reducible when every group already holds a single leaf", () => {
      const flat: TechniqueIntentMatrix = {
        "demon:Language:Code_and_encode:Token": {
          S005hate: { score: 0.9, passed: 90, total_evaluated: 100, nones: 0, n_detectors: 1 },
        },
      };
      const grouped = buildMatrixView(flat, "grouped");
      expect(grouped.reducible).toBe(false);
      // Grouped and leaf views collapse to the same single cell.
      expect(grouped.rows).toHaveLength(1);
      expect(buildMatrixView(flat, "leaf").rows).toHaveLength(1);
    });

    it("skips the reserved per-row _summary key", () => {
      const withSummary: TechniqueIntentMatrix = {
        "demon:Cat:Sub:A": {
          _summary: { n_intents: 1, n_detectors: 2 },
          X: { score: 0.5, passed: 50, total_evaluated: 100, nones: 0, n_detectors: 2 },
        },
      };
      const view = buildMatrixView(withSummary, "leaf");
      expect(view.cols).toEqual(["X"]); // _summary must not become a column
      expect(view.cell("demon:Cat:Sub:A", "X")!.nDetectors).toBe(2);
    });

    it("drops cells the digest left unevaluated (null score or zero evals)", () => {
      const sparse: TechniqueIntentMatrix = {
        "demon:Cat:Sub:A": {
          X: { score: null, passed: 0, total_evaluated: 0, nones: 0, n_detectors: 0 },
          Y: { score: 0.4, passed: 40, total_evaluated: 100, nones: 0, n_detectors: 1 },
        },
      };
      const view = buildMatrixView(sparse, "leaf");
      expect(view.cols).toEqual(["Y"]); // the null-score X pairing is excluded
      expect(view.cell("demon:Cat:Sub:A", "X")).toBeUndefined();
    });
  });

  it("names and describes leaf intents from the bundled trait typology", () => {
    const code = "C001"; // a real intent code present in the typology
    const named: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        _summary: { name: "Alpha technique", description: "Does alpha things", n_intents: 1, n_detectors: 1 },
        [code]: {
          name: "digest name (ignored when the typology knows the code)",
          score: 0.5,
          passed: 50,
          total_evaluated: 100,
          nones: 0,
          n_detectors: 1,
        },
      },
    };
    const view = buildMatrixView(named, "leaf");
    expect(view.rowLabel("demon:Cat:Sub:A")).toBe("Alpha technique");
    expect(view.colLabel(code), "intent label comes from the typology").toBe(intentName(code));
    expect(view.rowDescription("demon:Cat:Sub:A")).toBe("Does alpha things");
    expect(view.colDescription(code), "intent description comes from the typology").toBe(
      intentDescription(code),
    );
    // Grouped keys span many techniques, so technique names don't apply there.
    expect(buildMatrixView(named, "grouped").rowDescription("demon:Cat:Sub")).toBeUndefined();
  });

  it("falls back to the digest name then the raw code when the typology is silent", () => {
    const unknown: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        Znovel: { name: "Digest Only", score: 0.5, passed: 50, total_evaluated: 100, nones: 0, n_detectors: 1 },
        Zbare: { score: 0.5, passed: 50, total_evaluated: 100, nones: 0, n_detectors: 1 },
      },
    };
    const view = buildMatrixView(unknown, "leaf");
    expect(view.colLabel("Znovel"), "unknown code with a digest name uses it").toBe("Digest Only");
    expect(view.colLabel("Zbare"), "unknown code with no name falls back to the code").toBe("Zbare");
    expect(view.colDescription("Znovel"), "unknown code has no typology description").toBeUndefined();
  });

  it("labels grouped intent families with the typology name, not the raw code", () => {
    const family = "C002"; // family/subcategory code present in the typology
    const leaf = "C002deny"; // a leaf that rolls up into the C002 family
    const named: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        [leaf]: { name: "x", score: 0.5, passed: 50, total_evaluated: 100, nones: 0, n_detectors: 1 },
      },
    };
    const grouped = buildMatrixView(named, "grouped");
    expect(grouped.cols, "leaf rolls up to its hazard family").toContain(family);
    expect(grouped.colLabel(family), "grouped column uses the family name").toBe(intentName(family));
    expect(grouped.colLabel(family), "the raw code is not shown").not.toBe(family);
    expect(grouped.colDescription(family)).toBe(intentDescription(family));
  });

  it("attaches taxonomy descriptions to both technique and intent axis groups", () => {
    const code = "C001";
    const named: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        _summary: { name: "Alpha", description: "Alpha desc", n_intents: 1, n_detectors: 1 },
        [code]: {
          score: 0.5,
          passed: 50,
          total_evaluated: 100,
          nones: 0,
          n_detectors: 1,
        },
      },
    };
    const view = buildMatrixView(named, "leaf");
    expect(buildAxisGroups(view, "technique")[0].description).toBe("Alpha desc");
    expect(
      buildAxisGroups(view, "intent")[0].description,
      "intent groups surface the typology description",
    ).toBe(intentDescription(code));
  });

  it("pools passed / undetermined counts and keeps the worst detector count", () => {
    const pooled: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        S005hate: { score: 0.2, passed: 20, total_evaluated: 100, nones: 5, n_detectors: 3 },
      },
      "demon:Cat:Sub:B": {
        S005erotica: { score: 0.6, passed: 60, total_evaluated: 100, nones: 1, n_detectors: 2 },
      },
    };
    const cell = buildMatrixView(pooled, "grouped").cell("demon:Cat:Sub", "S005")!;
    expect(cell.score).toBe(0.2); // worst leaf
    expect(cell.passed).toBe(80); // summed
    expect(cell.nones).toBe(6); // summed
    expect(cell.nDetectors).toBe(3); // max across pooled leaves
  });

  it("sums distinct prompts across pooled leaves (defaulting to 0 when absent)", () => {
    const withPrompts: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        S005hate: { score: 0.2, passed: 20, total_evaluated: 100, nones: 0, n_attempts: 50, n_detectors: 2 },
      },
      "demon:Cat:Sub:B": {
        // older report fragment with no prompt count -> contributes 0
        S005erotica: { score: 0.6, passed: 60, total_evaluated: 100, nones: 0, n_detectors: 1 },
      },
    };
    const cell = buildMatrixView(withPrompts, "grouped").cell("demon:Cat:Sub", "S005")!;
    expect(cell.nAttempts, "prompts sum across pooled leaves").toBe(50);
  });
});

describe("buildAxisGroups", () => {
  it("groups by technique with worst-first intents nested inside", () => {
    const view = buildMatrixView(matrix, "grouped");
    const groups = buildAxisGroups(view, "technique");
    // The Roleplaying row holds the 0% cell, so it surfaces first.
    expect(groups[0].key).toBe("demon:Fictionalizing:Roleplaying");
    expect(groups[0].score).toBe(0); // worst child cell
    // Children are the intent families it was probed against, worst-first.
    expect(groups[0].cells[0].cell.score).toBe(0); // T009 (worst) before S005
    expect(groups[0].cells.map(c => c.otherKey)).toEqual(["T009", "S005"]);
  });

  it("sums evaluations across a group's cells", () => {
    const view = buildMatrixView(matrix, "grouped");
    const roleplaying = buildAxisGroups(view, "technique").find(
      g => g.key === "demon:Fictionalizing:Roleplaying",
    );
    // T009 cell (2620) + S005 cell (120) pooled.
    expect(roleplaying!.nEvaluations).toBe(2620 + 120);
  });

  it("sums distinct prompts across a group's cells", () => {
    const withPrompts: TechniqueIntentMatrix = {
      "demon:Cat:Sub:A": {
        X: { score: 0.5, passed: 50, total_evaluated: 100, nones: 0, n_attempts: 10, n_detectors: 1 },
        Y: { score: 0.4, passed: 40, total_evaluated: 100, nones: 0, n_attempts: 25, n_detectors: 1 },
      },
    };
    const group = buildAxisGroups(buildMatrixView(withPrompts, "leaf"), "technique")[0];
    expect(group.nAttempts, "group prompts = sum over its cells").toBe(35);
  });

  it("groups by intent with techniques nested inside", () => {
    const view = buildMatrixView(matrix, "grouped");
    const groups = buildAxisGroups(view, "intent");
    const t009 = groups.find(g => g.key === "T009");
    expect(t009).toBeDefined();
    // Only the Roleplaying subcategory pairs with T009 in the fixture.
    expect(t009!.cells.map(c => c.otherKey)).toEqual(["demon:Fictionalizing:Roleplaying"]);
    expect(t009!.score).toBe(0);
  });

  it("returns no groups for an empty matrix", () => {
    expect(buildAxisGroups(buildMatrixView({}, "grouped"), "technique")).toHaveLength(0);
  });
});

describe("findNotablePairings", () => {
  it("flags a combination that fails far worse than its row and column do elsewhere", () => {
    // Technique A is safe against X but collapses on Y; everything else is fine.
    const view = buildMatrixView(
      matrixOf([
        { t: "demon:Cat:Sub:A", i: "X", score: 1 },
        { t: "demon:Cat:Sub:A", i: "Y", score: 0 },
        { t: "demon:Cat:Other:B", i: "X", score: 0.95 },
        { t: "demon:Cat:Other:B", i: "Y", score: 0.9 },
      ]),
      "leaf",
    );
    const notable = findNotablePairings(view);
    expect(notable).toHaveLength(1); // only the A×Y interaction
    expect(notable[0].rowKey).toBe("demon:Cat:Sub:A");
    expect(notable[0].colKey).toBe("Y");
    expect(notable[0].gap).toBeCloseTo(0.9); // min(rowBest 1, colBest 0.9) - 0
  });

  it("returns nothing for a separable matrix (intent drives the score)", () => {
    // Both techniques behave identically; Y is bad for everyone -> no interaction.
    const view = buildMatrixView(
      matrixOf([
        { t: "demon:Cat:Sub:A", i: "X", score: 1 },
        { t: "demon:Cat:Sub:A", i: "Y", score: 0 },
        { t: "demon:Cat:Other:B", i: "X", score: 1 },
        { t: "demon:Cat:Other:B", i: "Y", score: 0 },
      ]),
      "leaf",
    );
    expect(findNotablePairings(view)).toHaveLength(0);
  });

  it("never flags single-cell rows/columns (no 'elsewhere' to compare)", () => {
    const view = buildMatrixView(matrixOf([{ t: "demon:Cat:Sub:A", i: "X", score: 0 }]), "leaf");
    expect(findNotablePairings(view)).toHaveLength(0);
  });

  it("orders by surprise (largest gap first) and respects the limit", () => {
    const view = buildMatrixView(
      matrixOf([
        { t: "demon:Cat:Sub:A", i: "X", score: 1 },
        { t: "demon:Cat:Sub:A", i: "Y", score: 0.1 }, // gap ~0.8
        { t: "demon:Cat:Other:B", i: "X", score: 1 },
        { t: "demon:Cat:Other:B", i: "Y", score: 0.9 },
        { t: "demon:Cat:Third:C", i: "X", score: 1 }, // gives C an "elsewhere"
        { t: "demon:Cat:Third:C", i: "Y", score: 0 }, // gap ~0.9 (vs colBest 0.9)
      ]),
      "leaf",
    );
    const notable = findNotablePairings(view, { limit: 1 });
    expect(notable).toHaveLength(1);
    expect(notable[0].colKey).toBe("Y");
    expect(notable[0].rowKey).toBe("demon:Cat:Third:C"); // largest gap surfaces first
  });
});
