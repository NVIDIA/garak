/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import TechniqueIntentProvenance from "../TechniqueIntentProvenance";
import type { ProbeDetectorPair } from "../../../types/ReportEntry";

describe("TechniqueIntentProvenance", () => {
  it("shows each probe once and opens it inside the report", () => {
    const pairs: ProbeDetectorPair[] = [
      ["grandma.Win10", "always.Fail"],
      ["grandma.Win10", "always.Pass"],
      ["grandma.Win11", "always.Fail"],
    ];
    const open = vi.fn();
    render(<TechniqueIntentProvenance pairs={pairs} onProbeSelect={open} />);
    expect(screen.getAllByRole("button"), "detectors do not duplicate probe pills").toHaveLength(2);
    fireEvent.click(screen.getByRole("button", { name: "Open grandma.Win10 in report" }));
    expect(open, "navigation uses the full probe identity").toHaveBeenCalledWith("grandma.Win10");
    expect(screen.queryByRole("table"), "probe references stay compact").toBeNull();
    expect(screen.queryByRole("link"), "references stay inside the report").toBeNull();
  });
});
