/**
 * @file DetectorFilters.tsx
 * @description DEFCON level filter controls for detector comparison charts.
 * @module components/DetectorChart
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Flex, Text } from "@kui/react";
import DefconBadge from "../DefconBadge";
import type { GroupedDetectorEntry } from "../../hooks/useGroupedDetectors";
import { DEFCON_LEVELS, CHART_OPACITY } from "../../constants";

/** Props for DetectorFilters component */
interface DetectorFiltersProps {
  entries: GroupedDetectorEntry[];
  onToggleDefcon: (defcon: number) => void;
  getDefconOpacity: (defcon: number) => number;
}

/**
 * DEFCON filter badges for toggling visibility of detector results.
 * Shows clickable badges for each DEFCON level present in the data.
 *
 * @param props - Component props
 * @param props.entries - Detector entries to count DEFCON distribution
 * @param props.onToggleDefcon - Callback when a DEFCON badge is clicked
 * @param props.getDefconOpacity - Function to get current opacity for each level
 * @returns Filter badge row or empty fragment if no DEFCON data
 */
const DetectorFilters = ({ entries, onToggleDefcon, getDefconOpacity }: DetectorFiltersProps) => {
  const hasDefconValues = DEFCON_LEVELS.some(
    defcon => entries.filter(e => e.detector_defcon === defcon).length > 0
  );

  return (
    <>
      {hasDefconValues && (
        <Flex gap="density-xs" align="center" paddingTop="density-md">
          <Text kind="label/regular/md">DEFCON:</Text>
          <Flex gap="density-xs" align="center">
            {DEFCON_LEVELS.map(defcon => {
              const count = entries.filter(e => e.detector_defcon === defcon).length;
              if (count === 0) return null;

              const opacity = getDefconOpacity(defcon);

              return (
                <Flex
                  key={defcon}
                  gap="density-xs"
                  align="center"
                  onClick={() => onToggleDefcon(defcon)}
                  style={{ opacity, cursor: "pointer" }}
                  title={`${count} entries at DEFCON ${defcon}. Click to ${opacity === CHART_OPACITY.full ? "hide" : "show"}.`}
                >
                  <DefconBadge defcon={defcon} size="sm" />
                  <span className="text-xs text-gray-500">({count})</span>
                </Flex>
              );
            })}
          </Flex>
        </Flex>
      )}
    </>
  );
};

export default DetectorFilters;
