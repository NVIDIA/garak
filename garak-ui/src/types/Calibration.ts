export type Calibration = {
  model_count: number;
  calibration_date: string;
  model_list: string;
};

export type CalibrationProps = {
  calibration: {
    calibration_date: string;
    model_count: number;
    model_list: string;
  };
};
