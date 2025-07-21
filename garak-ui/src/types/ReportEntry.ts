import type { ModuleData } from "./Module";

export type ReportEntry = {
  entry_type: "digest";
  filename: string;
  meta: {
    reportfile: string;
    garak_version: string;
    start_time: string;
    run_uuid: string;
    setup: Record<string, unknown>;
    calibration_used: boolean;
    aggregation_unknown?: boolean;
    calibration?: {
      calibration_date: string;
      model_count: number;
      model_list: string;
    };
  };
  eval: Record<string, any>;
  results?: ModuleData[];
};

export type CalibrationData = {
  calibration_date: string;
  model_count: number;
  model_list: string;
};

export type ReportDetailsProps = {
  setupData: Record<string, any> | null;
  calibrationData: CalibrationData | null;
};
