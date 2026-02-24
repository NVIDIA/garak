import { useSortedDetectors } from "../useSortedDetectors";
import type { Detector } from "../../types/ProbesChart";
import { describe, it, expect } from "vitest";

describe("useSortedDetectors", () => {
  it("sorts detectors by zscore, placing nulls last", () => {
    const sort = useSortedDetectors();

    const input: Detector[] = [
      {
        detector_name: "d2",
        detector_descr: "desc",
        absolute_score: 0,
        absolute_defcon: 0,
        absolute_comment: "",
        relative_score: null as unknown as number,
        relative_defcon: 0,
        relative_comment: "",
        detector_defcon: 0,
        calibration_used: false,
      },
      {
        detector_name: "d1",
        detector_descr: "desc",
        absolute_score: 0,
        absolute_defcon: 0,
        absolute_comment: "",
        relative_score: -1,
        relative_defcon: 0,
        relative_comment: "",
        detector_defcon: 0,
        calibration_used: false,
      },
      {
        detector_name: "d3",
        detector_descr: "desc",
        absolute_score: 0,
        absolute_defcon: 0,
        absolute_comment: "",
        relative_score: 2,
        relative_defcon: 0,
        relative_comment: "",
        detector_defcon: 0,
        calibration_used: false,
      },
    ];

    const result = sort(input);
    expect(result.map(d => d.detector_name)).toEqual(["d1", "d3", "d2"]);
  });

  it("sorts when b.zscore is null and a.zscore is valid", () => {
    const sort = useSortedDetectors();

    const input: Detector[] = [
      {
        detector_name: "d1",
        detector_descr: "desc",
        absolute_score: 0,
        absolute_defcon: 0,
        absolute_comment: "",
        relative_score: 1,
        relative_defcon: 0,
        relative_comment: "",
        detector_defcon: 0,
        calibration_used: false,
      },
      {
        detector_name: "d2",
        detector_descr: "desc",
        absolute_score: 0,
        absolute_defcon: 0,
        absolute_comment: "",
        relative_score: null as unknown as number,
        relative_defcon: 0,
        relative_comment: "",
        detector_defcon: 0,
        calibration_used: false,
      },
    ];

    const result = sort(input);
    expect(result.map(d => d.detector_name)).toEqual(["d1", "d2"]);
  });
});
