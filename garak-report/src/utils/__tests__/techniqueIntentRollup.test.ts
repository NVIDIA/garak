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
  buildMatrixView,
  rollupTaxonomyMap,
  restrictMapToLevelKeys,
} from "../techniqueIntentRollup";
import type { TaxonomyScoreMap, TechniqueIntentMatrix } from "../../types/ReportEntry";

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
    n_evaluations: c.total,
    detectors_used: [],
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
          S005hate: { score: 0.9, n_evaluations: 100, detectors_used: [] },
        },
      };
      const grouped = buildMatrixView(flat, "grouped");
      expect(grouped.reducible).toBe(false);
      // Grouped and leaf views collapse to the same single cell.
      expect(grouped.rows).toHaveLength(1);
      expect(buildMatrixView(flat, "leaf").rows).toHaveLength(1);
    });
  });
});

describe("rollupTaxonomyMap", () => {
  const techniqueMap: TaxonomyScoreMap = {
    "demon:Fictionalizing:Roleplaying:DAN_and_target_persona": {
      score: 0.25,
      n_evaluations: 2580,
      detectors_used: ["dan.DAN"],
      probes: ["dan.Dan_11_0"],
    },
    "demon:Fictionalizing:Roleplaying:User_persona": {
      score: 0,
      n_evaluations: 40,
      detectors_used: ["dan.DAN", "mitigation.Refusal"],
      probes: ["dan.AutoDAN"],
    },
    "demon:Language:Code_and_encode:Token": {
      score: 0.998,
      n_evaluations: 1850,
      detectors_used: ["safe.det"],
      probes: ["encoding.InjectBase64"],
    },
  };

  it("returns the map unchanged at leaf level (same reference)", () => {
    expect(rollupTaxonomyMap(techniqueMap, "technique", "leaf")).toBe(techniqueMap);
  });

  it("pools sibling techniques into a subcategory by their worst (min) score", () => {
    const rolled = rollupTaxonomyMap(techniqueMap, "technique", "grouped");
    // The two Roleplaying leaves collapse; Code_and_encode stays on its own.
    expect(Object.keys(rolled)).toHaveLength(2);
    const roleplaying = rolled["demon:Fictionalizing:Roleplaying"];
    expect(roleplaying.score).toBe(0); // worst of 0.25 and 0
    expect(roleplaying.n_evaluations).toBe(2620); // 2580 + 40 summed
    expect(roleplaying.detectors_used).toEqual(["dan.DAN", "mitigation.Refusal"]); // unioned
    expect(roleplaying.probes).toEqual(["dan.Dan_11_0", "dan.AutoDAN"]); // unioned
  });

  it("pools intent codes into their hazard family", () => {
    const intentMap: TaxonomyScoreMap = {
      S004lewd: { score: 0.9, n_evaluations: 100, detectors_used: [] },
      S004erotica: { score: 0.4, n_evaluations: 50, detectors_used: [] },
      S005hate: { score: 1, n_evaluations: 200, detectors_used: [] },
    };
    const rolled = rollupTaxonomyMap(intentMap, "intent", "grouped");
    expect(rolled.S004.score).toBe(0.4); // worst of the S004 variants
    expect(rolled.S004.n_evaluations).toBe(150);
    expect(rolled.S005.score).toBe(1);
  });
});

describe("restrictMapToLevelKeys", () => {
  // A technique present in the marginal but absent from the matrix (no intent
  // pairing) must be dropped so the bars match the heatmap rows.
  const techniqueMap: TaxonomyScoreMap = {
    "demon:Fictionalizing:Roleplaying:User_persona": { score: 0, n_evaluations: 40, detectors_used: [] },
    "demon:Language:Stylizing:Leetspeak": { score: 0.8, n_evaluations: 90, detectors_used: [] },
  };

  it("drops grouped keys that aren't heatmap rows", () => {
    const allowed = new Set(["demon:Fictionalizing:Roleplaying"]); // matrix only has this row
    const restricted = restrictMapToLevelKeys(techniqueMap, "technique", "grouped", allowed);
    expect(Object.keys(restricted)).toEqual(["demon:Fictionalizing:Roleplaying:User_persona"]);
  });

  it("matches on the leaf key itself at leaf level", () => {
    const allowed = new Set(["demon:Language:Stylizing:Leetspeak"]);
    const restricted = restrictMapToLevelKeys(techniqueMap, "technique", "leaf", allowed);
    expect(Object.keys(restricted)).toEqual(["demon:Language:Stylizing:Leetspeak"]);
  });
});
