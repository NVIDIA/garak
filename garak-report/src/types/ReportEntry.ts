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
 * Aggregated score entry for a technique or intent taxonomy bucket.
 * Mirrors the digest's `intent` / `technique` / `technique_intent` cell shape.
 * `score` is a 0-1 pass rate (higher is safer).
 */
export type TaxonomyScore = {
  score: number;
  n_evaluations: number;
  detectors_used: string[];
  aggregation?: string;
  source_aggregations?: string[];
  /** Present on top-level `intent` / `technique` buckets, absent on matrix cells. */
  probes?: string[];
};

/** Flat taxonomy map: bucket key (intent code or `demon:` technique) -> score. */
export type TaxonomyScoreMap = Record<string, TaxonomyScore>;

/** Nested technique -> intent -> score matrix from `digest.technique_intent`. */
export type TechniqueIntentMatrix = Record<string, Record<string, TaxonomyScore>>;

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
  /** Cross-cutting taxonomy sections (present on reports with technique/intent data). */
  intent?: TaxonomyScoreMap;
  technique?: TaxonomyScoreMap;
  technique_intent?: TechniqueIntentMatrix;
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
