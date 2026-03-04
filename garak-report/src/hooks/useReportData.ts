/**
 * @file useReportData.ts
 * @description Hook for loading and managing report data from build-time injection
 *              or runtime window.reportsData.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useEffect, useState } from "react";
import type { ReportEntry } from "../types/ReportEntry";
import type { Calibration } from "../types/Calibration";

/**
 * Build-time injected report data.
 * In production, Vite replaces __GARAK_INSERT_HERE__ with actual report JSON.
 */
// prettier-ignore
// @ts-expect-error: __GARAK_INSERT_HERE__ replaced at build time for production
const BUILD_REPORTS: ReportEntry[] = typeof __GARAK_INSERT_HERE__ !== "undefined" ? __GARAK_INSERT_HERE__ : [];

/**
 * Global window extension for runtime report data injection.
 */
declare global {
  interface Window {
    reportsData?: ReportEntry[];
  }
}

/**
 * Return type for useReportData hook
 */
export interface ReportDataState {
  /** Currently selected report entry */
  selectedReport: ReportEntry | null;
  /** Calibration data from the report */
  calibrationData: Calibration | null;
  /** Setup/configuration data from the report */
  setupData: Record<string, unknown> | null;
}

/**
 * Hook for loading and managing report data.
 * Prioritizes build-time injected data over runtime window.reportsData.
 *
 * @returns Report data state including selected report, calibration, and setup
 *
 * @example
 * ```tsx
 * const { selectedReport, calibrationData, setupData } = useReportData();
 * ```
 */
export function useReportData(): ReportDataState {
  const [selectedReport, setSelectedReport] = useState<ReportEntry | null>(null);
  const [calibrationData, setCalibrationData] = useState<Calibration | null>(null);
  const [setupData, setSetupData] = useState<Record<string, unknown> | null>(null);

  // Load report data on mount
  useEffect(() => {
    if (Array.isArray(BUILD_REPORTS) && BUILD_REPORTS.length > 0) {
      setSelectedReport(BUILD_REPORTS[0]);
    } else if (window.reportsData && Array.isArray(window.reportsData)) {
      setSelectedReport(window.reportsData[0]);
    }
  }, []);

  // Update calibration and setup when report changes
  useEffect(() => {
    setCalibrationData(selectedReport?.meta.calibration || null);
    setSetupData(selectedReport?.meta.setup || null);
  }, [selectedReport]);

  return { selectedReport, calibrationData, setupData };
}

