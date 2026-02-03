/**
 * @file ColorLegend.tsx
 * @description Color legend showing DEFCON level colors and labels.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import useSeverityColor from "../hooks/useSeverityColor";
import { Flex, Text, Button } from "@kui/react";

/** All DEFCON levels to display in legend */
const levels = [1, 2, 3, 4, 5];

/**
 * Displays a horizontal legend mapping colors to DEFCON severity labels.
 * Optionally includes a close button for dismissable display.
 *
 * @param props - Component props
 * @param props.onClose - Optional callback to dismiss the legend
 * @returns Color legend with severity labels
 */
const ColorLegend = ({ onClose }: { onClose?: () => void }) => {
  const { getSeverityColorByLevel, getSeverityLabelByLevel } = useSeverityColor();

  return (
    <Flex gap="density-xl">
      {levels.map(l => (
        <Flex key={l} align="center" gap="density-xs">
          <div
            style={{
              background: getSeverityColorByLevel(l),
              width: 14,
              height: 14,
              borderRadius: 2,
              flexShrink: 0,
            }}
            aria-label={getSeverityLabelByLevel(l)}
          />
          <Text kind="body/regular/sm">{getSeverityLabelByLevel(l)}</Text>
        </Flex>
      ))}
      {onClose && (
        <Flex justify="end">
          <Button kind="tertiary" size="small" onClick={onClose} aria-label="Hide legend">
            ×
          </Button>
        </Flex>
      )}
    </Flex>
  );
};

export default ColorLegend;
