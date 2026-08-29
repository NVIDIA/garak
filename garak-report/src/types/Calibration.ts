/**
 * @file Calibration.ts
 * @description Type definitions for calibration data and component props.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Calibration metadata from Garak's model comparison baseline.
 */
export type Calibration = {
  /** Number of models used in calibration set */
  model_count: number;
  /** ISO date string of calibration */
  calibration_date: string;
  /** Comma-separated model identifiers */
  model_list: string;
};

/** Props for CalibrationSummary component */
export type CalibrationProps = {
  calibration: {
    calibration_date: string;
    model_count: number;
    model_list: string;
  };
};
