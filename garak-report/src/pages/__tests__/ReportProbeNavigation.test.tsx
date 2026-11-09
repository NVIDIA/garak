/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { dispatch, option } from "../../components/TechniqueIntent/__tests__/heatmapFixtures";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { StrictMode } from "react";
import Report from "../Report";
import type { ReportEntry } from "../../types/ReportEntry";

const data = vi.hoisted(() => ({ report: null as ReportEntry | null }));
vi.mock("../../hooks/useReportData", () => ({
  useReportData: () => ({ selectedReport: data.report, setupData: {}, calibrationData: null }),
}));

describe("report probe navigation", () => {
  beforeEach(() => {
    vi.spyOn(window, "scrollBy").mockImplementation(() => {});
  });
  afterEach(() => vi.restoreAllMocks());
  it.each([0.5, 1])(
    "opens probes in their actual report group, including hidden groups (%s)",
    async score => {
      const defcon = score === 1 ? 5 : 3;
      const probe = (name: string) => ({
        _summary: {
          probe_name: name,
          probe_score: score,
          probe_severity: defcon,
          probe_descr: "Contributing probe",
          probe_tier: 1,
        },
        "example.Check": { detector_name: "example.Check", absolute_score: score },
      });
      data.report = {
        entry_type: "digest",
        filename: "navigation.json",
        meta: {
          reportfile: "navigation.jsonl",
          garak_version: "test",
          start_time: "2026-11-09",
          run_uuid: "navigation",
          setup: {
            "reporting.show_100_pass_modules": false,
            "reporting.bootstrap_min_sample_size": 5,
          },
          calibration_used: false,
        },
        eval: {
          "custom grouping": {
            _summary: {
              group: "custom grouping",
              score,
              group_defcon: defcon,
              doc: "",
              group_link: "",
              group_aggregation_function: "mean",
              unrecognised_aggregation_function: false,
              show_top_group_score: true,
            },
            "probe.One": probe("probe.One"),
            "probe.Two": probe("probe.Two"),
          },
        },
        technique_intent_matrix: {
          technique: Object.fromEntries(
            ["One", "Two"].map(name => [
              name,
              {
                score,
                passed: score * 10,
                total_evaluated: 10,
                nones: 0,
                probe_detector_pairs: [[`probe.${name}`, "example.Check"]],
              },
            ])
          ),
        },
      };
      render(
        <StrictMode>
          <Report currentTheme="dark" />
        </StrictMode>
      );
      const summaryText = () =>
        screen.queryByText(/modules evaluated|modules are below DC-3/)?.textContent ?? null;
      const originalSummary = summaryText();
      fireEvent.click(screen.getByTitle(`DEFCON ${defcon}. Click to hide.`));
      for (const name of ["One", "Two", "One"]) {
        fireEvent.mouseDown(screen.getByRole("tab", { name: "Techniques & Intents" }), {
          button: 0,
          ctrlKey: false,
        });
        fireEvent.click(screen.getByRole("tab", { name: "Techniques & Intents" }));
        await screen.findByRole("grid", { name: "Technique by intent pass rates" });
        expect(
          screen.getByText("Fewer than 5 evaluations"),
          "the legend uses this report's sample-count setting"
        ).toBeVisible();
        expect(
          option.series[0].data[0].itemStyle.decal,
          "ten evaluations exceed the report's configured threshold"
        ).toBeUndefined();
        dispatch("click", {
          componentType: "series",
          data: { rowKey: "technique", colKey: name, value: [0, 0, score] },
        });
        fireEvent.click(screen.getByRole("button", { name: `Open probe.${name} in report` }));
        expect(
          screen.getByRole("tab", { name: "Modules" }),
          "the report changes tab"
        ).toHaveAttribute("aria-selected", "true");
        expect(summaryText(), "opening a probe does not change report totals").toBe(
          originalSummary
        );
        const detail = screen.getByRole("region", { name: `probe.${name} probe details` });
        expect(detail, "the linked probe is expanded").toBeVisible();
        expect(detail, "keyboard focus follows navigation").toHaveFocus();
        expect(
          within(detail).getByText("example.Check"),
          "even passing detectors are available at the destination"
        ).toBeVisible();
        expect(
          screen.getByTitle(`DEFCON ${defcon}. Click to hide.`),
          "the destination's DEFCON filter is enabled"
        ).toBeVisible();
      }
    }
  );
});
