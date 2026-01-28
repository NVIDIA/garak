/**
 * @file useDetectorChartOptions.ts
 * @description Hook to build ECharts options for detector lollipop chart.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import type { Probe, ChartDetector, ChartPointData, ChartLineData } from "../types/ProbesChart";
import type { GroupedDetectorEntry } from "../types/Detector";
import { useTooltipFormatter } from "./useTooltipFormatter";
import { useDetectorsChartSeries } from "./useDetectorsChartSeries";
import useSeverityColor from "./useSeverityColor";
import {
  THEME_COLORS,
  CHART_DIMENSIONS,
  CHART_SYMBOL_SIZES,
  CHART_LINE_WIDTHS,
  CHART_BORDER_WIDTHS,
  CHART_SHADOW,
  CHART_OPACITY,
} from "../constants";

/** Return type for detector chart options hook */
export interface DetectorChartOptionsResult {
  /** ECharts option configuration */
  option: Record<string, unknown>;
  /** Visible entries after filtering */
  visible: ChartDetector[];
  /** Chart height based on visible entries */
  chartHeight: number;
}

/**
 * Converts GroupedDetectorEntry to ChartDetector format.
 * @param entry - Grouped detector entry
 * @returns Chart-compatible detector data
 */
function toChartDetector(entry: GroupedDetectorEntry): ChartDetector {
  return {
    label: entry.label,
    probeName: entry.probeName,
    zscore: entry.zscore,
    detector_score: entry.detector_score,
    comment: entry.comment,
    color: entry.color,
    // Convert source names to display names (compute failures from passed)
    attempt_count: entry.total_evaluated,
    hit_count: entry.total_evaluated != null && entry.passed != null 
      ? entry.total_evaluated - entry.passed 
      : null,
    unavailable: entry.unavailable,
    detector_defcon: entry.detector_defcon,
    absolute_defcon: entry.absolute_defcon,
    relative_defcon: entry.relative_defcon,
  };
}

/**
 * Builds ECharts options for detector lollipop chart visualization.
 *
 * @param probe - Currently selected probe
 * @param detectorType - Type of detector being visualized
 * @param entries - Detector entries to display
 * @param hideUnavailable - Whether to hide N/A entries
 * @param isDark - Whether dark theme is active
 * @returns Chart options, visible entries, and computed height
 */
export function useDetectorChartOptions(
  probe: Probe,
  detectorType: string,
  entries: GroupedDetectorEntry[],
  hideUnavailable: boolean,
  isDark?: boolean
): DetectorChartOptionsResult {
  const buildSeries = useDetectorsChartSeries();
  const formatTooltip = useTooltipFormatter();
  const { getDefconColor } = useSeverityColor();
  const textColor = isDark ? THEME_COLORS.text.dark : THEME_COLORS.text.light;

  // Convert and sort entries by zscore
  const sortedDetectors = useMemo(
    () =>
      entries
        .map(toChartDetector)
        .sort((a, b) => b.label.localeCompare(a.label)), // Reverse alphabetical (A at bottom, Z at top)
    [entries]
  );

  const { pointSeries, lineSeries, naSeries, visible } = useMemo(
    () => buildSeries(sortedDetectors, hideUnavailable),
    [buildSeries, sortedDetectors, hideUnavailable]
  );

  const yAxisLabels = useMemo(
    () =>
      visible.map(d => {
        let label = d.label;
        if (d.attempt_count != null && d.hit_count != null) {
          label = `${d.label} (${d.hit_count}/${d.attempt_count})`;
        }
        return label;
      }),
    [visible]
  );

  // Check if selected probe is in visible array
  const selectedProbeInVisible = useMemo(
    () => visible.some(d => d.probeName === probe.probe_name),
    [visible, probe.probe_name]
  );

  // Build enhanced series with selection highlighting
  const option = useMemo(() => {
    const enhancedPointData: ChartPointData[] = pointSeries.data.map((point, index) => {
      const isSelected = selectedProbeInVisible && visible[index]?.probeName === probe.probe_name;
      const detectorDefcon = visible[index]?.detector_defcon ?? 0;

      return {
        ...point,
        symbolSize: isSelected ? CHART_SYMBOL_SIZES.selected : CHART_SYMBOL_SIZES.normal,
        itemStyle: {
          ...point.itemStyle,
          borderWidth: isSelected ? CHART_BORDER_WIDTHS.selected : CHART_BORDER_WIDTHS.normal,
          borderColor: isSelected ? getDefconColor(detectorDefcon) : "transparent",
          shadowBlur: isSelected ? CHART_SHADOW.blur.selected : CHART_SHADOW.blur.normal,
          shadowColor: isSelected ? getDefconColor(detectorDefcon) : "transparent",
        },
      };
    });

    const enhancedLineData: ChartLineData[] = lineSeries.data.map((line, index) => {
      const isSelected = selectedProbeInVisible && visible[index]?.probeName === probe.probe_name;
      const detectorDefcon = visible[index]?.detector_defcon ?? 0;
      const originalColor = line.itemStyle?.color ?? line.value[2] ?? "#999";

      return {
        ...line,
        lineStyle: {
          width: isSelected ? CHART_LINE_WIDTHS.selected : CHART_LINE_WIDTHS.normal,
          color: isSelected ? getDefconColor(detectorDefcon) : originalColor,
        },
      };
    });

    return {
      grid: {
        containLabel: CHART_DIMENSIONS.detectorGrid.containLabel,
        left: CHART_DIMENSIONS.detectorGrid.left,
        right: CHART_DIMENSIONS.detectorGrid.right,
        top: CHART_DIMENSIONS.detectorGrid.top,
        bottom: CHART_DIMENSIONS.detectorGrid.bottom,
      },
      tooltip: {
        trigger: "item",
        formatter: (params: { data: ChartDetector }) =>
          formatTooltip({ data: params.data, detectorType }),
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
        triggerEvent: true,
        axisLabel: {
          fontSize: CHART_DIMENSIONS.axis.fontSize,
          color: textColor,
          rich: {
            selected1: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(1),
            },
            selected2: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(2),
            },
            selected3: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(3),
            },
            selected4: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(4),
            },
            selected5: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(5),
            },
            dimmed: {
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: textColor,
              opacity: CHART_OPACITY.dimmed,
            },
          },
          formatter: (value: string, index: number) => {
            const isSelected =
              selectedProbeInVisible && visible[index]?.probeName === probe.probe_name;
            const detectorDefcon = visible[index]?.detector_defcon ?? 0;

            if (!isSelected) {
              return `{dimmed|${value}}`;
            }

            return `{selected${detectorDefcon}|${value}}`;
          },
        },
        axisLine: { lineStyle: { color: textColor } },
      },
      series: [
        { ...lineSeries, data: enhancedLineData },
        { ...pointSeries, data: enhancedPointData },
        naSeries,
      ],
    };
  }, [
    pointSeries,
    lineSeries,
    naSeries,
    selectedProbeInVisible,
    visible,
    probe.probe_name,
    getDefconColor,
    formatTooltip,
    detectorType,
    textColor,
    isDark,
    yAxisLabels,
  ]);

  const chartHeight = Math.max(
    CHART_DIMENSIONS.detector.minHeight,
    CHART_DIMENSIONS.detector.rowHeight * visible.length + CHART_DIMENSIONS.detector.extraSpace
  );

  return { option, visible, chartHeight };
}
