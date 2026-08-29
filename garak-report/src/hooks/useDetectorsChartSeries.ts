/**
 * @file useDetectorsChartSeries.ts
 * @description Hook to build ECharts series data for detector comparison charts.
 *              Creates line, point, and N/A series for lollipop visualization.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type {
  ChartDetector,
  ChartPointSeries,
  ChartLineSeries,
  ChartSeriesResult,
} from "../types/ProbesChart";
import theme from "../styles/theme";
import { useZScoreHelpers } from "./useZScoreHelpers";
import { useRenderLineItem } from "./useRenderLineItem";

/**
 * Builds ECharts series data for the "lollipop" detector comparison charts.
 *
 * Creates three series:
 * - Line series: Horizontal lines from 0 to Z-score
 * - Point series: Dots at Z-score endpoints
 * - N/A series: Special markers for unavailable data
 *
 * Handles optional hiding of unavailable data and returns the filtered visible items.
 *
 * @returns Function that transforms detector data into ECharts series configuration
 */
export function useDetectorsChartSeries() {
  const { clampZ } = useZScoreHelpers();
  const renderLineItem = useRenderLineItem();
  const isUnavailable = (d: ChartDetector) => d.comment === "Unavailable";

  return function buildSeries(
    detectors: ChartDetector[],
    hideUnavailable: boolean
  ): ChartSeriesResult {
    const visible = hideUnavailable ? detectors.filter(d => !isUnavailable(d)) : detectors;

    const pointSeries: ChartPointSeries = {
      type: "scatter",
      symbolSize: 10,
      data: visible.map((d, index) => ({
        value: [typeof d.zscore === "number" ? clampZ(d.zscore) : 0, index],
        name: d.label,
        zscore: d.zscore,
        detector_score: d.detector_score,
        comment: d.comment,
        attempt_count: d.attempt_count,
        hit_count: d.hit_count,
        itemStyle: {
          color: d.color === theme.colors.tk150 ? "rgba(156,163,175,0.3)" : d.color,
        },
      })),
    };

    const lineSeries: ChartLineSeries = {
      type: "custom",
      renderItem: renderLineItem,
      encode: { x: 0, y: 1 },
      data: visible.map((d, index) => ({
        value: [
          typeof d.zscore === "number" ? clampZ(d.zscore) : 0,
          index,
          d.color === theme.colors.tk150 ? "rgba(156,163,175,0.3)" : d.color,
        ],
        name: d.label,
        zscore: d.zscore,
        detector_score: d.detector_score,
        comment: d.comment,
        attempt_count: d.attempt_count,
        hit_count: d.hit_count,
        itemStyle: {
          color: d.color === theme.colors.tk150 ? "rgba(156,163,175,0.3)" : d.color,
        },
      })),
    };

    const naSeries = {
      type: "scatter" as const,
      data: hideUnavailable
        ? []
        : detectors
            .filter(d => d.comment === "Unavailable")
            .map(d => ({
              value: [0, d.label],
              name: d.label,
              zscore: d.zscore,
              detector_score: d.detector_score,
              comment: d.comment,
              symbol: "rect",
              symbolSize: [30, 20],
              label: {
                show: true,
                formatter: "N/A",
                color: "#444",
                fontSize: 10,
              },
              itemStyle: {
                color: theme.colors.tk150,
                borderColor: "#999",
                borderWidth: 1,
              },
            })),
    };

    return { pointSeries, lineSeries, naSeries, visible };
  };
}
