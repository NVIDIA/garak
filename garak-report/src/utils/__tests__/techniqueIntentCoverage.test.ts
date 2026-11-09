/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { describe, expect, it } from "vitest";
import { buildAxisGroups, buildMatrixView } from "../techniqueIntentRollup";
import type { ProbeDetectorPair } from "../../types/ReportEntry";

const result = (pairs: ProbeDetectorPair[], score = 1) => ({
  score,
  passed: score * 10,
  total_evaluated: 10,
  nones: 0,
  probe_detector_pairs: pairs,
});

describe("technique/intent evidence coverage", () => {
  it("detects overlapping provenance even when row scores differ", () => {
    const view = buildMatrixView({
      a: {
        X: result(
          [
            ["shared", "d"],
            ["onlyA", "d"],
          ],
          0.5
        ),
      },
      b: {
        X: result([
          ["shared", "d"],
          ["onlyB", "d"],
        ]),
      },
    });
    expect(view.sharedResults, "a shared probe/detector for the same intent reuses evidence").toBe(
      true
    );
  });

  it("does not infer shared evidence from matching percentages or different intents", () => {
    const view = buildMatrixView({
      a: { X: result([["p", "d"]]), Y: result([["p", "d"]]) },
      b: { X: result([["other", "d"]]) },
    });
    expect(
      view.sharedResults,
      "matching rates and one family are not proof of shared results"
    ).toBe(false);
  });

  it("keeps an all-undetermined intent and its contributing probes", () => {
    const pairs: ProbeDetectorPair[] = [["p", "d"]];
    const view = buildMatrixView({
      t: {
        X: {
          name: "Execute a file",
          score: null,
          passed: 0,
          total_evaluated: 0,
          nones: 210,
          probe_detector_pairs: pairs,
        },
      },
    });
    expect(view.cols, "an intent that ran without verdicts remains visible").toEqual(["X"]);
    expect(
      view.cell("t", "X"),
      "undetermined results keep their count and provenance"
    ).toMatchObject({ score: null, nones: 210, probeDetectorPairs: pairs });
    expect(
      buildAxisGroups(view, "intent")[0].score,
      "no verdict means no group risk score"
    ).toBeNull();
  });

  it("orders custom intent codes naturally and presents names first", () => {
    const view = buildMatrixView({
      t: {
        custom10: { ...result([], 0), name: "Later intent" },
        custom2: { ...result([]), name: "Earlier intent" },
      },
    });
    expect(view.cols, "code order stays stable independently of pass rate").toEqual([
      "custom2",
      "custom10",
    ]);
    expect(view.colName("custom2"), "axis labels lead with the supplied name").toBe(
      "Earlier intent"
    );
    expect(view.colLabel("custom2"), "full labels retain the code as secondary information").toBe(
      "Earlier intent (custom2)"
    );
  });
});
