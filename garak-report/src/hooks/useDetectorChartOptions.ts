/**
 * @file useDetectorChartOptions.ts
 * @description Hook to build ECharts options for detector lollipop chart.
 *              Displays Z-score comparison across detectors within a single probe.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import type { Detector } from "../types/ProbesChart";
import { useTooltipFormatter } from "./useTooltipFormatter";
import useSeverityColor from "./useSeverityColor";
import {
  THEME_COLORS,
  CHART_DIMENSIONS,
  CHART_SYMBOL_SIZES,
  CHART_LINE_WIDTHS,
} from "../constants";

/** Return type for detector chart options hook */
export interface DetectorChartOptionsResult {
  /** ECharts option configuration */
  option: Record<string, unknown>;
  /** Chart height based on number of detectors */
  chartHeight: number;
  /** Whether there is data to display */
  hasData: boolean;
}

/** Internal chart data structure */
interface ChartDetectorData {
  name: string;
  zscore: number | null;
  detector_score: number | null;
  comment: string;
  color: string;
  defcon: number;
  total: number;
  failed: number;  // Direct from backend (hit_count)
}

/**
 * Builds ECharts options for detector lollipop chart visualization.
 * Shows Z-score comparison across detectors within a single probe.
 *
 * @param detectors - Detectors from the selected probe
 * @param isDark - Whether dark theme is active
 * @param hoveredDetector - Currently hovered detector name for highlighting
 * @returns Chart options, height, and data availability flag
 */
export function useDetectorChartOptions(
  detectors: Detector[],
  isDark?: boolean,
  hoveredDetector?: string | null
): DetectorChartOptionsResult {
  const formatTooltip = useTooltipFormatter();
  const { getDefconColor } = useSeverityColor();
  const textColor = isDark ? THEME_COLORS.text.dark : THEME_COLORS.text.light;

  // Convert detectors to chart data format - ALL values direct from backend
  const chartData = useMemo<ChartDetectorData[]>(() => {
    return detectors.map((d) => {
      const zscore = d.relative_score;
      const zscoreIsValid = zscore != null && typeof zscore === "number" && !isNaN(zscore);
      
      // Get values from backend
      const total = d.total_evaluated ?? d.attempt_count ?? 0;
      // Failures: use hit_count if available, otherwise derive from passed
      const failures = d.hit_count ?? (total - (d.passed ?? total));

      return {
        name: d.detector_name,
        zscore: zscoreIsValid ? zscore : null,
        detector_score: d.absolute_score != null ? d.absolute_score * 100 : null,
        comment: d.relative_comment ?? "Unknown",
        color: zscoreIsValid
          ? getDefconColor(d.detector_defcon ?? 5)  // Match DEFCON badge color
          : "#999999", // Gray for unavailable
        defcon: d.detector_defcon ?? 5,
        total,
        failed: failures,  // Direct from backend (hit_count)
      };
    }).sort((a, b) => b.name.localeCompare(a.name)); // Reverse alpha for A at bottom
  }, [detectors, getDefconColor]);

  // Check if we have any valid data
  const hasData = chartData.some((d) => d.zscore !== null);

  // Build Y-axis labels (just detector names - counts shown in results table)
  const yAxisLabels = useMemo(
    () => chartData.map((d) => d.name),
    [chartData]
  );

  // Build series data
  const { pointData, lineData, naData } = useMemo(() => {
    const points: unknown[] = [];
    const lines: unknown[] = [];
    const naMarkers: unknown[] = [];

    // Clamp value to chart range
    const clamp = (val: number) =>
      Math.max(CHART_DIMENSIONS.zscore.min, Math.min(CHART_DIMENSIONS.zscore.max, val));

    chartData.forEach((d, index) => {
      const isHovered = hoveredDetector === d.name;
      const isFaded = hoveredDetector !== null && !isHovered;
      const opacity = isFaded ? 0.2 : 1;

      // N/A marker for detectors without Z-score
      if (d.zscore === null) {
        naMarkers.push({
          value: [0, index],
          name: d.name,
          detector_defcon: d.defcon,
          failed: d.failed,
          total: d.total,
          comment: "No calibration data",
          itemStyle: {
            color: "#666666",
            borderWidth: 1,
            borderColor: "#888888",
            opacity,
          },
          symbol: "rect",
          symbolSize: [32, 16],
          label: {
            show: true,
            formatter: "N/A",
            fontSize: 11,
            fontWeight: "bold",
            color: "#ffffff",
          },
        });
        return;
      }

      const clampedZscore = clamp(d.zscore);

      // Point (dot at the end of lollipop)
      points.push({
        value: [clampedZscore, index],
        name: d.name,
        zscore: d.zscore, // Keep original for tooltip
        detector_score: d.detector_score,
        comment: d.comment,
        detector_defcon: d.defcon,
        failed: d.failed,
        total: d.total,
        itemStyle: {
          color: d.color,
          borderWidth: 2,
          borderColor: getDefconColor(d.defcon),
          opacity,
        },
        symbolSize: isHovered ? CHART_SYMBOL_SIZES.normal + 4 : CHART_SYMBOL_SIZES.normal,
      });

      // Line (stem from 0 to clamped value)
      lines.push({
        value: [clampedZscore, index, d.color, opacity],
        name: d.name,
        zscore: d.zscore, // Keep original for tooltip
        detector_score: d.detector_score,
        comment: d.comment,
        detector_defcon: d.defcon,
        failed: d.failed,
        total: d.total,
        lineStyle: {
          width: isHovered ? CHART_LINE_WIDTHS.normal + 1 : CHART_LINE_WIDTHS.normal,
          color: d.color,
          opacity,
        },
      });
    });

    return { pointData: points, lineData: lines, naData: naMarkers };
  }, [chartData, getDefconColor, hoveredDetector]);

  // Build chart option
  const option = useMemo(
    () => ({
      grid: {
        containLabel: CHART_DIMENSIONS.detectorGrid.containLabel,
        left: CHART_DIMENSIONS.detectorGrid.left,
        right: CHART_DIMENSIONS.detectorGrid.right,
        top: CHART_DIMENSIONS.detectorGrid.top,
        bottom: CHART_DIMENSIONS.detectorGrid.bottom,
      },
      tooltip: {
        trigger: "item",
        formatter: (params: { data: { name: string; zscore?: number | null; detector_score?: number | null; comment?: string | null; detector_defcon?: number; passed?: number; failed?: number; total?: number; itemStyle?: { color?: string } } }) =>
          formatTooltip({
            data: {
              ...params.data,
              zscore: params.data.zscore ?? undefined,
              detector_score: params.data.detector_score ?? undefined,
              comment: params.data.comment ?? undefined,
            },
            detectorType: params.data.name,
          }),
        confine: true,
      },
      xAxis: {
        type: "value",
        min: CHART_DIMENSIONS.zscore.min,
        max: CHART_DIMENSIONS.zscore.max,
        nameTextStyle: { color: textColor },
        axisLabel: { color: textColor },
        axisLine: { lineStyle: { color: textColor } },
        splitLine: {
          lineStyle: {
            color: isDark ? THEME_COLORS.chart.splitLine.dark : THEME_COLORS.chart.splitLine.light,
          },
        },
      },
      yAxis: {
        type: "category",
        data: yAxisLabels,
        axisLabel: {
          fontSize: CHART_DIMENSIONS.axis.fontSize,
          color: textColor,
          rich: {
            // Defcon-colored styles for labels (normal)
            dc1: { fontWeight: "bold", color: getDefconColor(1) },
            dc2: { fontWeight: "bold", color: getDefconColor(2) },
            dc3: { fontWeight: "bold", color: getDefconColor(3) },
            dc4: { fontWeight: "bold", color: getDefconColor(4) },
            dc5: { fontWeight: "bold", color: getDefconColor(5) },
            // Faded styles for non-hovered labels (20% opacity via rgba)
            faded1: { fontWeight: "bold", color: "rgba(185, 28, 28, 0.2)" }, // red faded
            faded2: { fontWeight: "bold", color: "rgba(250, 204, 21, 0.2)" }, // yellow faded
            faded3: { fontWeight: "bold", color: "rgba(96, 165, 250, 0.2)" }, // blue faded
            faded4: { fontWeight: "bold", color: "rgba(34, 197, 94, 0.2)" }, // green faded
            faded5: { fontWeight: "bold", color: "rgba(45, 212, 191, 0.2)" }, // teal faded
          },
          formatter: (value: string, index: number) => {
            const detector = chartData[index];
            if (!detector) return value;
            const defcon = detector.defcon;
            const isFaded = hoveredDetector !== null && hoveredDetector !== detector.name;
            const stylePrefix = isFaded ? "faded" : "dc";
            return `{${stylePrefix}${defcon}|${value}}`;
          },
        },
        axisLine: { lineStyle: { color: textColor } },
        triggerEvent: true, // Enable hover events on Y-axis labels
      },
      series: [
        // Line series (stems)
        {
          type: "custom",
          renderItem: (
            _params: { coordSys: { x: number; width: number } },
            api: {
              value: (dim: number) => number;
              coord: (val: [number, number]) => [number, number];
              visual: (key: string) => string;
            }
          ) => {
            const xValue = api.value(0);
            const yValue = api.value(1);
            const color = api.value(2) as unknown as string; // color stored in value[2]
            const opacity = api.value(3) as unknown as number; // opacity stored in value[3]
            const start = api.coord([0, yValue]);
            const end = api.coord([xValue, yValue]);

            return {
              type: "line",
              shape: {
                x1: start[0],
                y1: start[1],
                x2: end[0],
                y2: end[1],
              },
              style: {
                stroke: color,
                lineWidth: CHART_LINE_WIDTHS.normal,
                opacity: opacity ?? 1,
              },
            };
          },
          encode: { x: 0, y: 1 },
          data: lineData,
        },
        // Point series (dots)
        {
          type: "scatter",
          symbolSize: CHART_SYMBOL_SIZES.normal,
          data: pointData,
        },
        // N/A markers for detectors without Z-score
        {
          type: "scatter",
          data: naData,
        },
      ],
    }),
    [chartData, yAxisLabels, pointData, lineData, naData, formatTooltip, getDefconColor, textColor, isDark, hoveredDetector]
  );

  const chartHeight = Math.max(
    CHART_DIMENSIONS.detector.minHeight,
    CHART_DIMENSIONS.detector.rowHeight * chartData.length + CHART_DIMENSIONS.detector.extraSpace
  );

  return { option, chartHeight, hasData };
}
