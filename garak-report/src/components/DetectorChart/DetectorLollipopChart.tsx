/**
 * @file DetectorLollipopChart.tsx
 * @description Lollipop chart showing Z-score comparison across probes for a detector type.
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
import type { Probe } from "../../types/ProbesChart";
import type { GroupedDetectorEntry } from "../../hooks/useGroupedDetectors";
import type { EChartsTooltipParams } from "../../types/echarts.d";
import { useDetectorChartOptions } from "../../hooks/useDetectorChartOptions";

/** Props for DetectorLollipopChart component */
interface DetectorLollipopChartProps {
  /** Currently selected probe */
  probe: Probe;
  /** All probes for cross-comparison */
  allProbes: Probe[];
  /** Detector type name being visualized */
  detectorType: string;
  /** Filtered detector entries to display */
  entries: GroupedDetectorEntry[];
  /** Whether to hide N/A entries */
  hideUnavailable: boolean;
  /** Callback when a probe is clicked */
  onProbeClick: (probe: Probe) => void;
  /** Theme mode for styling */
  isDark?: boolean;
}

/**
 * Lollipop chart comparing Z-scores across probes for a specific detector type.
 * Highlights the selected probe and handles click interactions for probe switching.
 *
 * @param props - Component props
 * @returns Lollipop chart with click handling, or empty state message
 */
const DetectorLollipopChart = ({
  probe,
  allProbes,
  detectorType,
  entries,
  hideUnavailable,
  onProbeClick,
  isDark,
}: DetectorLollipopChartProps) => {
  const chartRef = useRef<ReactECharts>(null);
  const [zeroXPosition, setZeroXPosition] = useState<number | null>(null);

  const { option, visible, chartHeight } = useDetectorChartOptions(
    probe,
    detectorType,
    entries,
    hideUnavailable,
    isDark
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

  /**
   * Handles click events on chart elements or axis labels.
   */
  const handleClick = (params: EChartsTooltipParams) => {
    let clickedLabel = params.name;

    // Handle axis label clicks
    if (params.componentType === "yAxis") {
      clickedLabel = params.value as string;
      const match = clickedLabel.match(/^(.+?)\s*\(\d+\/\d+\)$/);
      if (match) {
        clickedLabel = match[1];
      }
    }

    const match = allProbes.find(p => p.probe_name.includes(clickedLabel));
    if (match) onProbeClick(match);
  };

  const isEmpty = visible.length === 0 || visible.every(d => d.zscore === null);

  return (
    <>
      {/* Chart header - always shown */}
      <Flex align="center" gap="density-xxs">
        <Text kind="mono/sm">{probe.probe_name}</Text>
        <Text kind="mono/sm">//</Text>
        <Text kind="title/sm">{detectorType}</Text>
        <Divider />
      </Flex>

      {/* Empty state */}
      {isEmpty ? (
        <Flex paddingTop="density-2xl">
          <StatusMessage
            size="small"
            slotMedia={<i className="nv-icons-fill-warning"></i>}
            slotHeading="No Data Available"
            slotSubheading={
              <Stack gap="density-sm">
                <Text kind="label/regular/md">
                  All detector results for this comparison are unavailable (N/A).
                </Text>
                <Text kind="label/regular/sm">
                  Try unchecking "Hide N/A" to see unavailable entries, change DEFCON levels or select
                  a different detector.
                </Text>
              </Stack>
            }
          />
        </Flex>
      ) : (
        <>
          {/* Chart */}
          <ReactECharts
            ref={chartRef}
            option={option}
            style={{ height: chartHeight }}
            onEvents={{ click: handleClick }}
            onChartReady={handleChartReady}
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
    </>
  );
};

export default DetectorLollipopChart;
