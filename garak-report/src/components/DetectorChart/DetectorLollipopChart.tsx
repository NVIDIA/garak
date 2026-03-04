/**
 * @file DetectorLollipopChart.tsx
 * @description Lollipop chart showing Z-score comparison across detectors within a probe.
 *              Displays horizontal lines from zero to Z-score value with dot endpoints.
 * @module components/DetectorChart
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useRef, useState, useCallback } from "react";
import ReactECharts from "echarts-for-react";
import { Button, Divider, Flex, Stack, StatusMessage, Text, Tooltip } from "@kui/react";
import { Info } from "lucide-react";
import type { Detector } from "../../types/ProbesChart";
import { useDetectorChartOptions } from "../../hooks/useDetectorChartOptions";

/** Props for DetectorLollipopChart component */
interface DetectorLollipopChartProps {
  /** Detectors to display (from the probe) */
  detectors: Detector[];
  /** Theme mode for styling */
  isDark?: boolean;
  /** Currently hovered detector name (for linked highlighting) */
  hoveredDetector?: string | null;
  /** Callback when detector is hovered */
  onHoverDetector?: (name: string | null) => void;
}

/**
 * Lollipop chart comparing Z-scores across detectors within a probe.
 * Shows relative performance of each detector against the average.
 *
 * @param props - Component props
 * @returns Lollipop chart, or empty state message if no data
 */
const DetectorLollipopChart = ({
  detectors,
  isDark,
  hoveredDetector,
  onHoverDetector,
}: DetectorLollipopChartProps) => {
  const chartRef = useRef<ReactECharts>(null);
  const [zeroXPosition, setZeroXPosition] = useState<number | null>(null);

  const { option, chartHeight, hasData } = useDetectorChartOptions(
    detectors,
    isDark,
    hoveredDetector
  );

  /** Calculate the pixel X position of 0 on the chart after render */
  const handleChartReady = useCallback(() => {
    if (chartRef.current) {
      const chart = chartRef.current.getEchartsInstance();
      try {
        const pos = chart.convertToPixel("grid", [0, 0]);
        if (pos && pos[0]) {
          setZeroXPosition(pos[0]);
        }
      } catch {
        // Chart not ready yet, ignore
      }
    }
  }, []);

  return (
    <Stack gap="density-lg">
      {/* Section header */}
      <Stack gap="density-xs">
        <Flex align="center" gap="density-xxs">
          <Text kind="title/sm">Relative Performance</Text>
          <Divider />
        </Flex>
        <Text kind="body/regular/sm" style={{ color: "var(--color-tk-400)" }}>
          Compared against calibration models
        </Text>
      </Stack>

      {/* Empty state */}
      {!hasData ? (
        <Flex>
          <StatusMessage
            size="small"
            slotMedia={<i className="nv-icons-fill-warning"></i>}
            slotHeading="No Calibration Data"
            slotSubheading={
              <Text kind="label/regular/md">
                Z-score comparison is not available for these detectors.
              </Text>
            }
          />
        </Flex>
      ) : (
        <>
          {/* Chart */}
          <ReactECharts
            ref={chartRef}
            option={option}
            style={{ height: chartHeight, cursor: "default" }}
            onChartReady={handleChartReady}
            onEvents={{
              mouseover: (params: { componentType?: string; data?: { name?: string }; value?: string }) => {
                // Handle data point hover
                if (params.data?.name) {
                  onHoverDetector?.(params.data.name);
                }
                // Handle Y-axis label hover
                else if (params.componentType === "yAxis" && params.value) {
                  // Extract detector name from label (format: "name (passed/total)")
                  const match = params.value.match(/^(.+?)\s*\(/);
                  const name = match ? match[1] : params.value;
                  // Find matching detector
                  const detector = detectors.find(d => d.detector_name === name || d.detector_name.includes(name));
                  if (detector) {
                    onHoverDetector?.(detector.detector_name);
                  }
                }
              },
              mouseout: () => {
                onHoverDetector?.(null);
              },
            }}
          />

          {/* Z-Score axis label with info tooltip - positioned at x=0 on chart */}
          <Flex
            align="center"
            gap="density-xxs"
            style={{
              position: "relative",
              left: zeroXPosition != null ? `${zeroXPosition}px` : "50%",
              transform: "translateX(-50%)",
              width: "fit-content",
              marginTop: "-4px",
            }}
          >
            <Text kind="label/regular/sm">Z-Score</Text>
            <Tooltip
              slotContent={
                <Stack gap="density-xxs">
                  <Text kind="body/bold/sm">Understanding Z-Scores</Text>
                  <Text kind="body/regular/sm">
                    Positive Z-scores mean better than average, negative Z-scores mean worse than average.
                  </Text>
                  <Text kind="body/regular/sm">
                    "Average" is determined over a bag of models of varying sizes, updated periodically.
                  </Text>
                  <Text kind="body/regular/sm">
                    For any probe, roughly two-thirds of models get a Z-score between -1.0 and +1.0.
                  </Text>
                  <Text kind="body/regular/sm">
                    The middle 10% of models score -0.125 to +0.125. This is labeled "competitive".
                  </Text>
                  <Text kind="body/regular/sm">
                    A Z-score of +1.0 means the score was one standard deviation better than the mean
                    score other models achieved for this probe & metric.
                  </Text>
                </Stack>
              }
            >
              <Button kind="tertiary" size="small">
                <Info size={14} />
              </Button>
            </Tooltip>
          </Flex>
        </>
      )}
    </Stack>
  );
};

export default DetectorLollipopChart;
