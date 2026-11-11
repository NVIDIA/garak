/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import CellDetail from "../TechniqueIntentCellDetail";
import type { MatrixCell } from "../../../utils/techniqueIntentRollup";
const cell: MatrixCell = {
  row: "t",
  col: "i",
  score: 0.4,
  passed: 40,
  nEvaluations: 100,
  nones: 5,
  nAttempts: 20,
  nDetectors: 3,
};
describe("TechniqueIntentCellDetail", () => {
  it("does not subtract undetermined results from evaluated failures", () => {
    render(<CellDetail cell={cell} />);
    expect(
      screen.getByText("Failed").parentElement,
      "100 evaluated minus 40 passed gives 60 failures"
    ).toHaveTextContent("Failed60");
    expect(
      screen.getByText("Undetermined").parentElement,
      "undetermined results stay separate"
    ).toHaveTextContent("Undetermined5");
  });
  it("reports heterogeneous prompt and detector coverage without inventing an equality", () => {
    render(<CellDetail cell={cell} />);
    expect(screen.getByText("20 prompts · 3 detectors · 100 evaluations.")).toBeVisible();
    expect(screen.queryByText(/ = /), "coverage does not imply a product").toBeNull();
  });
  it("handles older digests without prompt counts", () => {
    render(<CellDetail cell={{ ...cell, nAttempts: 0 }} />);
    expect(screen.queryByText("Prompts")).toBeNull();
    expect(
      screen.getByText("Counts are detector evaluations, pooled across 3 detectors.")
    ).toBeVisible();
    expect(
      screen.queryByText("Probes used"),
      "older reports do not invent probe references"
    ).toBeNull();
  });
  it("shows a passing state for a fully passing pairing", () => {
    render(<CellDetail cell={{ ...cell, score: 1, passed: 100, nones: 0 }} />);
    expect(screen.getByText("No failures recorded")).toBeVisible();
    expect(screen.queryByText("Undetermined")).toBeNull();
  });
});
