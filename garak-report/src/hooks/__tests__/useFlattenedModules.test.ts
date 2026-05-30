import { renderHook } from "@testing-library/react";
import useFlattenedModules from "../useFlattenedModules";
import { describe, it, expect } from "vitest";
import type { ReportEntry } from "../../types/ReportEntry";
import type { Detector } from "../../types/ProbesChart";

const mockReport: ReportEntry = {
  entry_type: "digest",
  filename: "r.jsonl",
  meta: {
    reportfile: "r.jsonl",
    garak_version: "1.0",
    start_time: "now",
    run_uuid: "u",
    setup: {},
    calibration_used: false,
  },
  eval: {
    groupA: {
      _summary: {
        score: 0.5,
        group: "groupA",
        group_defcon: 2,
        doc: "",
        group_link: "",
        group_aggregation_function: "max",
        unrecognised_aggregation_function: false,
        show_top_group_score: true,
      },
      probe1: {
        _summary: {
          probe_name: "p1",
          probe_score: 0.6,
          probe_severity: 2,
          probe_descr: "",
          probe_tier: 1,
        },
        detectorX: { absolute_score: 0.6 },
      },
    },
  },
};

describe("useFlattenedModules", () => {
  it("flattens groups, probes, detectors", () => {
    const { result } = renderHook(() => useFlattenedModules(mockReport));
    expect(result.current.length).toBe(1);
    const mod = result.current[0];
    expect(mod.group_name).toBe("groupA");
    expect(mod.probes.length).toBe(1);
    expect(mod.probes[0].detectors.length).toBe(1);
  });

  it("includes 100% groups when show_100_pass_modules flag true", () => {
    const report: ReportEntry = JSON.parse(JSON.stringify(mockReport));
    report.eval.groupB = {
      _summary: {
        score: 1,
        group: "groupB",
        group_defcon: 5,
        doc: "",
        group_link: "",
        group_aggregation_function: "max",
        unrecognised_aggregation_function: false,
        show_top_group_score: true,
      },
    };
    report.meta.setup = { "reporting.show_100_pass_modules": true };
    const { result } = renderHook(() => useFlattenedModules(report));
    expect(result.current.find(m => m.group_name === "groupB")).toBeTruthy();
  });

  it("skips detectors with high absolute score when show100Pass false", () => {
    const report: ReportEntry = JSON.parse(JSON.stringify(mockReport));
    const groupA = report.eval.groupA;
    if (groupA && typeof groupA === "object" && "probe1" in groupA) {
      const probe1 = groupA.probe1;
      if (probe1 && typeof probe1 === "object") {
        (probe1 as Record<string, unknown>).detectorY = { absolute_score: 1.2 };
      }
    }
    const { result } = renderHook(() => useFlattenedModules(report));
    const detectors = result.current[0].probes[0].detectors;
    expect(detectors.find((d: Detector) => d.detector_name === "detectorY")).toBeUndefined();
  });

  it("sets unrecognised_aggregation_function when aggregation_unknown true", () => {
    const report: ReportEntry = JSON.parse(JSON.stringify(mockReport));
    report.meta.aggregation_unknown = true;
    const { result } = renderHook(() => useFlattenedModules(report));
    expect(result.current[0].summary.unrecognised_aggregation_function).toBe(true);
  });

  it("respects show_top_group_score flag false", () => {
    const report: ReportEntry = JSON.parse(JSON.stringify(mockReport));
    report.meta.setup = { "reporting.show_top_group_score": false };
    const { result } = renderHook(() => useFlattenedModules(report));
    expect(result.current[0].summary.show_top_group_score).toBe(false);
  });

  it("returns empty array when report is null", () => {
    const { result } = renderHook(() => useFlattenedModules(null));
    expect(result.current).toEqual([]);
  });
});
