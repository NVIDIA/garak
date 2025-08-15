export type Detector = {
  detector_name: string;
  detector_descr: string;
  absolute_score: number;
  absolute_defcon: number;
  absolute_comment: string;
  zscore: number;
  zscore_defcon: number;
  zscore_comment: string;
  detector_defcon: number;
  calibration_used: boolean;
};

export type Probe = {
  probe_name: string;
  summary: {
    probe_name: string;
    probe_score: number;
    probe_severity: number;
    probe_descr: string;
    probe_tier: number;
  };
  detectors: Detector[];
};

export type Module = {
  group_name: string;
  summary: {
    group: string;
    score: number;
    group_defcon: number;
    doc: string;
    group_link: string;
    group_aggregation_function: string;
    unrecognised_aggregation_function: boolean;
    show_top_group_score: boolean;
  };
  probes: Probe[];
};

export type ProbesChartProps = {
  module: Module;
  selectedProbe: Probe | null;
  setSelectedProbe: (probe: Probe | null) => void;
};

export type ChartDetector = {
  label: string;
  probeName?: string;
  zscore: number;
  detector_score: number | null;
  comment: string | null;
  color: string;
  attempt_count?: number | null;
  hit_count?: number | null;
  unavailable?: boolean;
  detector_defcon?: number | null;
  absolute_defcon?: number | null;
  zscore_defcon?: number | null;
};
