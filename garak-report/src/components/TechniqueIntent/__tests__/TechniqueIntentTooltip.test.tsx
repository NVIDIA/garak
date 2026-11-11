/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * @file TechniqueIntentTooltip.test.tsx
 * @description Checks pairing preview identity, score meaning and missing data.
 */

import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import TechniqueIntentTooltip from "../TechniqueIntentTooltip";
import { buildMatrixView } from "../../../utils/techniqueIntentRollup";

const measured = { score: 0, passed: 0, total_evaluated: 10, nones: 2, n_detectors: 2 };
const view = buildMatrixView(
  {
    t1: { _summary: { name: "Target persona", n_intents: 1, n_detectors: 2 }, i1: measured },
    t2: { i2: { ...measured, score: 1, passed: 10, nones: 0 } },
  },
  { i1: { name: "Disinformation", descr: "Present false claims as fact." } }
);

describe("TechniqueIntentTooltip", () => {
  it("identifies both axes and explains measured failures", () => {
    render(<TechniqueIntentTooltip view={view} technique="t1" intent="i1" />);
    expect(screen.getByText("Technique"), "axis roles are explicit").toBeVisible();
    expect(screen.getByText("Target persona"), "the full technique name is present").toBeVisible();
    expect(screen.getByText("Intent"), "intent has its own label").toBeVisible();
    expect(
      screen.getByText(/i1 - Disinformation/),
      "intent code and name are retained"
    ).toBeVisible();
    expect(screen.getByText("0%"), "zero remains a measured result").toBeVisible();
    expect(screen.getByText("DC-1"), "risk uses the report's existing scale").toBeVisible();
    expect(screen.getByText("Critical Risk"), "the risk name is explicit").toBeVisible();
    expect(
      screen.getByRole("tooltip").textContent,
      "counts refer to evaluations rather than prompts"
    ).toContain("0 of 10 detector evaluations passed");
    expect(screen.getByText(/^10 failed/), "failures remain explicit").toBeVisible();
    expect(
      screen.getByText(/2 undetermined \(excluded from pass rate\)/),
      "unknown verdicts stay separate"
    ).toBeVisible();
    expect(
      screen.getByText("Present false claims as fact."),
      "available intent context is included"
    ).toBeVisible();
  });

  it("shows an untested intersection without inventing a score or risk", () => {
    render(<TechniqueIntentTooltip view={view} technique="t1" intent="i2" />);
    expect(screen.getByText("Not evaluated"), "missing data has its own state").toBeVisible();
    expect(
      screen.getByText("No results for this pairing."),
      "missing data is explained"
    ).toBeVisible();
    expect(screen.queryByText("Observed pass rate"), "missing data is not a zero rate").toBeNull();
    expect(screen.queryByText(/DC-/), "untested pairings have no risk class").toBeNull();
  });

  it("omits an empty undetermined count for fully determined results", () => {
    render(<TechniqueIntentTooltip view={view} technique="t2" intent="i2" />);
    expect(screen.getByText("100%"), "perfect pass rates remain explicit").toBeVisible();
    expect(
      screen.queryByText(/undetermined/),
      "empty metadata does not crowd the preview"
    ).toBeNull();
    expect(
      screen.getByText("Select cell for full details below."),
      "selection offers persistent details"
    ).toBeVisible();
  });

  it.each([1, 11, 12, 200])("qualifies %s evaluations using the supplied count threshold", n => {
    const sample = buildMatrixView({
      t: { i: { ...measured, score: 1, passed: n, total_evaluated: n, nones: 0 } },
    });
    render(<TechniqueIntentTooltip view={sample} technique="t" intent="i" minEvaluations={12} />);
    expect(
      screen.getByText("Observed pass rate"),
      "the percentage describes observed outcomes"
    ).toBeVisible();
    expect(
      screen.getByText(`${n} of ${n} detector ${n === 1 ? "evaluation" : "evaluations"} passed`),
      "the rate is accompanied by its actual denominator"
    ).toBeVisible();
    expect(
      screen.queryByText("Low evaluation count") !== null,
      "only counts below the report threshold receive a badge"
    ).toBe(n < 12);
    expect(
      screen.queryByText("n < 12") !== null,
      "the threshold is stated rather than implying statistical confidence"
    ).toBe(n < 12);
  });
});
