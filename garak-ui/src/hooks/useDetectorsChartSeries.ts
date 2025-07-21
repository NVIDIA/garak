// src/hooks/useDetectorsChartSeries.ts
import type { ChartDetector } from "../types/ProbesChart";
import theme from "../styles/theme";
import { useZScoreHelpers } from "./useZScoreHelpers";
import { useRenderLineItem } from "./useRenderLineItem";

export function useDetectorsChartSeries() {
  const { clampZ } = useZScoreHelpers();
  const renderLineItem = useRenderLineItem();
  const isUnavailable = (d: ChartDetector) => d.comment === "Unavailable";

  return function buildSeries(detectors: ChartDetector[], hideUnavailable: boolean) {
    const sorted = [...detectors]; // assume already sorted
    const visible = hideUnavailable ? detectors.filter(d => !isUnavailable(d)) : detectors;

    const pointSeries = {
      type: "scatter",
      symbolSize: 10,
      data: visible.map(d => ({
        value: [clampZ(d.zscore!), d.label],
        name: d.label,
        zscore: d.zscore,
        detector_score: d.detector_score,
        comment: d.comment,
        itemStyle: {
          color:
            d.color === theme.colors.tk150 ? "rgba(156,163,175,0.3)" : d.color,
        },
      })),
    };

    const lineSeries = {
      type: "custom",
      renderItem: renderLineItem,
      encode: { x: 0, y: 1 },
      data: visible.map(d => ({
        value: [clampZ(d.zscore!), d.label, d.color === theme.colors.tk150 ? "rgba(156,163,175,0.3)" : d.color],
        name: d.label,
        zscore: d.zscore,
        detector_score: d.detector_score,
        comment: d.comment,
        itemStyle: {
          color:
            d.color === theme.colors.tk150 ? "rgba(156,163,175,0.3)" : d.color,
        },
      })),
    };

    const naSeries = {
      type: "scatter",
      data: hideUnavailable
        ? []
        : sorted
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
