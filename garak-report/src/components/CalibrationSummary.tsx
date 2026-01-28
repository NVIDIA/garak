/**
 * @file CalibrationSummary.tsx
 * @description Tabbed display of calibration metadata and model list.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { CalibrationProps } from "../types/Calibration";
import { Tabs, Text, Stack, Flex } from "@kui/react";

/**
 * Displays calibration information in a tabbed interface.
 * Shows summary statistics and expandable model list.
 *
 * @param props - Component props
 * @param props.calibration - Calibration metadata object
 * @returns Tabbed calibration display
 */
const CalibrationSummary = ({ calibration }: CalibrationProps) => {
  return (
    <Tabs
      items={[
        {
          value: "summary",
          children: "Calibration Summary",
          slotContent: (
            <Stack gap="density-xl">
              <Flex gap="density-xs" align="center">
                <Text kind="label/bold/sm" className="whitespace-nowrap">
                  Date:
                </Text>
                <Text kind="body/regular/sm" className="flex-1">
                  {new Date(calibration.calibration_date).toLocaleString()}
                </Text>
              </Flex>
              <Flex gap="density-xs" align="center">
                <Text kind="label/bold/sm" className="whitespace-nowrap">
                  Model Count:
                </Text>
                <Text kind="body/regular/sm" className="flex-1">
                  {calibration.model_count}
                </Text>
              </Flex>
            </Stack>
          ),
        },
        {
          value: "models",
          children: "Calibration Models",
          slotContent: (
            <Stack gap="density-xs">
              <Text kind="label/bold/sm">Models:</Text>
              <Stack gap="density-xs">
                {calibration.model_list.split(", ").map((model: string, index: number) => (
                  <Text key={index} kind="body/regular/sm">
                    {model}
                  </Text>
                ))}
              </Stack>
            </Stack>
          ),
        },
      ]}
    />
  );
};

export default CalibrationSummary;
