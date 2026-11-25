/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import TechniqueIntentAxisTooltip from "../TechniqueIntentAxisTooltip";
import { buildAxisGroups, buildMatrixView } from "../../../utils/techniqueIntentRollup";

const measured = {
  name: "Degrade output",
  score: 0,
  passed: 0,
  total_evaluated: 208,
  nones: 2,
  probe_detector_pairs: [["probe.One", "detector.One"]] as [string, string][],
};

describe("shared-evidence previews", () => {
  it("reports weakest-pairing counts once when three technique tags reuse the result", () => {
    const view = buildMatrixView({ a: { X: measured }, b: { X: measured }, c: { X: measured } });
    render(
      <TechniqueIntentAxisTooltip
        group={buildAxisGroups(view, "intent")[0]}
        axis="intent"
        total={3}
      />
    );
    const worst = within(screen.getByRole("group", { name: "Weakest pairing" }));
    expect(
      worst.getByText("0 of 208 detector evaluations passed"),
      "counts belong to one stated pairing"
    ).toBeVisible();
    expect(
      worst.getByText(/208 failed · 2 undetermined/),
      "shared outcomes are not counted three times"
    ).toBeVisible();
    expect(
      screen.queryByText(/624/),
      "technique memberships must not inflate evaluation totals"
    ).toBeNull();
    expect(screen.getByText("3 of 3"), "technique coverage is reported separately").toBeVisible();
  });

  it("does not invent a weakest score when all pairings are undetermined", () => {
    const cell = { ...measured, score: null, total_evaluated: 0, nones: 210 };
    const view = buildMatrixView({ a: { X: cell }, b: { X: cell } });
    render(
      <TechniqueIntentAxisTooltip
        group={buildAxisGroups(view, "intent")[0]}
        axis="intent"
        total={2}
      />
    );
    expect(
      screen.getByText("No determinate results"),
      "a missing verdict has no rankable score"
    ).toBeVisible();
    expect(
      screen.getByText("2 pairings undetermined"),
      "coverage includes processed pairings"
    ).toBeVisible();
    expect(screen.queryByText(/DC-/), "unknown outcomes receive no DEFCON band").toBeNull();
  });
});
