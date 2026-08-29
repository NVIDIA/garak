/**
 * @file CalibrationSummary.ts
 * @description Props type for CalibrationSummary component (alternative format).
 * @module types
 *
 * @see CalibrationProps in Calibration.ts for standard format
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Alternative props format for calibration display.
 * @deprecated Consider using CalibrationProps from Calibration.ts
 */
export type CalibrationSummaryProps = {
  calibration: {
    /** Calibration date string */
    date: string;
    /** Number of calibration models */
    model_count: number;
    /** Array of model names (differs from comma-separated string in CalibrationProps) */
    model_list: string[];
  };
};
