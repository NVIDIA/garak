/**
 * @file ReportEntry.ts
 * @description Type definitions for Garak report digest entries.
 *              Represents the top-level structure of parsed report data.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { ModuleData } from "./Module";
import type { EvalData } from "./Eval";

/**
 * One technique×intent cell from `digest.technique_intent_matrix`. `score` is a
 * 0-1 pass rate (higher is safer) or `null` when nothing was evaluated. The
 * digest pools detectors into a count (`n_detectors`); it does not carry their
 * names at this granularity.
 */
export type TechniqueIntentCell = {
  score: number | null;
  passed: number;
  total_evaluated: number;
  nones: number;
  n_detectors: number;
};

/** Per-technique roll-up carried under the reserved `_summary` key of each row. */
export type TechniqueIntentRowSummary = {
  n_intents: number;
  n_detectors: number;
};

/**
 * One technique's row: a `_summary` plus intent-code -> cell entries. The
 * `_summary` key is reserved and must be skipped when iterating intents.
 */
export type TechniqueIntentRow = {
  _summary?: TechniqueIntentRowSummary;
  [intent: string]: TechniqueIntentCell | TechniqueIntentRowSummary | undefined;
};

/** `demon:` technique -> intent code -> cell, from `digest.technique_intent_matrix`. */
export type TechniqueIntentMatrix = Record<string, TechniqueIntentRow>;

/**
 * Root structure for a Garak report digest.
 * Contains metadata, configuration, and evaluation results.
 */
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
    // New fields
    probespec?: string;
    target_type?: string;
    target_name?: string;
    model_type?: string; // Fallback for older reports
    model_name?: string; // Fallback for older reports
    payloads?: string[];
    group_aggregation_function?: string;
    report_digest_time?: string;
  };
  eval: EvalData;
  results?: ModuleData[];
  /** Pooled technique×intent matrix (present on reports with technique/intent data). */
  technique_intent_matrix?: TechniqueIntentMatrix;
};

/**
 * Calibration metadata from the Garak calibration process.
 * Used to compare model performance against baseline.
 */
export type CalibrationData = {
  /** ISO date string of when calibration was performed */
  calibration_date: string;
  /** Number of models in the calibration set */
  model_count: number;
  /** Comma-separated list of calibration model names */
  model_list: string;
};

/**
 * Props for the ReportDetails component.
 * Combines setup, calibration, and metadata for display.
 */
export type ReportDetailsProps = {
  setupData: Record<string, unknown> | null;
  calibrationData: CalibrationData | null;
  meta: ReportEntry["meta"];
};
