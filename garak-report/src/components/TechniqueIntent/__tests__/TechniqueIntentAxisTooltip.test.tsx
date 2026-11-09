/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * @file TechniqueIntentTooltip.test.tsx
 * @description Checks pairing preview identity, score meaning and missing data.
 */

import { render, screen, within } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import TechniqueIntentAxisTooltip from "../TechniqueIntentAxisTooltip";
import { buildAxisGroups, buildMatrixView } from "../../../utils/techniqueIntentRollup";

const measured = { score: 0, passed: 0, total_evaluated: 10, nones: 2, n_detectors: 2 };
const view = buildMatrixView(
  {
    t1: { _summary: { name: "Target persona", n_intents: 1, n_detectors: 2 }, i1: measured },
    t2: { i2: { ...measured, score: 1, passed: 10, nones: 0 } },
  },
  { i1: { name: "Disinformation", descr: "Present false claims as fact." } }
);

describe("TechniqueIntentAxisTooltip", () => {
  it.each(["technique", "intent"] as const)(
    "previews a complete %s with explicit coverage and worst score",
    axis => {
      const key = axis === "technique" ? "t1" : "i1";
      const group = buildAxisGroups(view, axis).find(item => item.key === key)!;
      render(<TechniqueIntentAxisTooltip group={group} axis={axis} total={2} />);
      const totals = screen.getByRole("group", { name: "Across tested pairings" });
      expect(
        screen.getByText(axis === "intent" ? "Disinformation" : group.label),
        "the full axis name is visible"
      ).toBeVisible();
      expect(
        within(screen.getByRole("group", { name: "Weakest pairing" })).getByText("0%"),
        "the score is not presented as a pooled rate"
      ).toBeVisible();
      expect(
        within(screen.getByRole("group", { name: "Across tested pairings" })).getByText("1 of 2"),
        "coverage includes unevaluated intersections"
      ).toBeVisible();
      expect(
        within(totals).getByText("10 of 10"),
        "totals come from evaluated children"
      ).toBeVisible();
      expect(
        screen.getByText(group.cells[0].otherLabel),
        "the worst pairing is identified"
      ).toBeVisible();
      expect(
        screen.getByText(`Click ${axis === "technique" ? "row" : "column"} to inspect details.`),
        "selection guidance matches the hovered axis"
      ).toBeVisible();
    }
  );

  it("keeps a worst score separate from pooled counts and discloses tied pairings", () => {
    const mixed = buildMatrixView({
      t: { a: measured, b: measured, c: { ...measured, score: 1, passed: 10, nones: 0 } },
    });
    const group = buildAxisGroups(mixed, "technique")[0];
    render(<TechniqueIntentAxisTooltip group={group} axis="technique" total={4} />);
    expect(screen.getByText("0%"), "the existing worst-child score is retained").toBeVisible();
    expect(
      screen.getByRole("group", { name: "Across tested pairings" }).textContent,
      "pooled counts include passing pairings"
    ).toContain("20 of 30");
    expect(
      screen.getByText("1 other pairing at this pass rate."),
      "ties do not imply a unique worst child"
    ).toBeVisible();
    expect(screen.getByText("3 of 4"), "untested pairings stay outside the counts").toBeVisible();
  });
});
