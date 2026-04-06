/**
 * @file DetectorResultsTable.tsx
 * @description Table showing detector results with DEFCON badges and stacked progress bars.
 * @module components/DetectorChart
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Divider, Flex, Stack, Text, Tooltip } from "@kui/react";
import type { Detector } from "../../types/ProbesChart";
import DefconBadge from "../DefconBadge";
import ProgressBar from "../ProgressBar";
import { formatPercentage } from "../../utils/formatPercentage";

/** Props for DetectorResultsTable component */
interface DetectorResultsTableProps {
  /** Detectors to display in the table */
  detectors: Detector[];
  /** Currently hovered detector name (for linked highlighting) */
  hoveredDetector?: string | null;
  /** Callback when detector is hovered */
  onHoverDetector?: (name: string | null) => void;
}

/**
 * Table displaying detector results with DEFCON severity and stacked progress bars.
 * Green = passed, Red = failed. All on single line per detector.
 *
 * @param props - Component props
 * @returns Results table with detector metrics and progress visualization
 */
const DetectorResultsTable = ({
  detectors,
  hoveredDetector,
  onHoverDetector,
}: DetectorResultsTableProps) => {
  return (
    <Stack gap="density-lg">
      <Flex align="center" gap="density-xxs">
        <Text kind="title/sm">Detector Breakdown</Text>
        <Divider />
      </Flex>
      <Stack gap="density-md">
        {detectors.map((detector) => {
          const isHovered = hoveredDetector === detector.detector_name;
          const isFaded = hoveredDetector !== null && !isHovered;
          
          // Get values from backend
          const total = detector.total_evaluated ?? detector.attempt_count ?? 0;
          const passRate = detector.absolute_score ?? 0;  // Backend-computed pass rate
          
          // Failures: use hit_count if available, otherwise derive from passed
          // Backend provides either hit_count (failures) or passed (successes)
          const failures = detector.hit_count ?? (total - (detector.passed ?? total));
          
          // Presentation formatting only (decimal to percentage for display)
          const passPercent = passRate * 100;

          return (
            <Flex
              key={detector.detector_name}
              align="center"
              gap="density-md"
              onMouseEnter={() => onHoverDetector?.(detector.detector_name)}
              onMouseLeave={() => onHoverDetector?.(null)}
              style={{
                opacity: isFaded ? 0.3 : 1,
                transition: "opacity 0.15s ease",
              }}
            >
              {/* DEFCON badge - fixed width */}
              <div style={{ width: "52px", flexShrink: 0 }}>
                <DefconBadge defcon={detector.detector_defcon} />
              </div>

              {/* Detector name - mono font for technical identifier */}
              <Text
                kind="mono/sm"
                style={{
                  width: "280px",
                  flexShrink: 0,
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  color: "var(--color-tk-700)",
                }}
                title={detector.detector_name}
              >
                {detector.detector_name}
              </Text>

              {/* Stacked progress bar with tooltip */}
              <Tooltip
                slotContent={
                  <Stack gap="density-xxs">
                    <Text kind="body/bold/sm">{detector.detector_name}</Text>
                    <Text kind="body/regular/sm">
                      <span style={failures > 0 ? { color: "var(--color-red-400)" } : undefined}>{failures} failures</span>
                      {" / "}
                      <span>{total} total</span>
                    </Text>
                    <Text kind="body/regular/sm">
                      Pass rate: {formatPercentage(passPercent)}
                    </Text>
                  </Stack>
                }
              >
                <div style={{ flex: 1, minWidth: "200px", cursor: "help" }}>
                  <ProgressBar passPercent={passPercent} hasFailures={failures > 0} />
                </div>
              </Tooltip>

              {/* Counts: failures/total and pass rate - all from backend */}
              <Flex align="center" gap="density-sm" style={{ flexShrink: 0 }}>
                <Text kind="mono/sm" style={{ color: "var(--color-tk-500)" }}>
                  <span style={failures > 0 ? { color: "var(--color-red-500)" } : undefined}>{failures}</span>
                  <span style={{ color: "var(--color-tk-400)" }}> / {total}</span>
                </Text>
                <Text kind="mono/sm" style={{ color: "var(--color-tk-400)", width: "52px", textAlign: "right" }}>
                  {formatPercentage(passPercent)}
                </Text>
              </Flex>
            </Flex>
          );
        })}
      </Stack>
    </Stack>
  );
};

export default DetectorResultsTable;
