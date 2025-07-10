export type Calibration = {
  model_count: number;
  date: string | number | Date;
};

export type CalibrationProps = {
  calibration: {
    calibration_date: string;
    model_count: number;
    model_list: string;
  };
};
