/**
 * @file ProbeChartHeader.tsx
 * @description Header component for probe chart with title and info tooltip.
 * @module components/ProbeChart
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Button, Flex, Stack, Text, Tooltip } from "@kui/react";
import { Info } from "lucide-react";
import ColorLegend from "../ColorLegend";

/**
 * Header for probe score chart with explanatory tooltip.
 * Tooltip explains what probes are and how to interpret the chart.
 *
 * @returns Chart header with title and info button
 */
const ProbeChartHeader = () => {
  return (
    <Flex align="center" gap="density-xxs">
      <Text kind="title/xs">Probe scores</Text>
      <Tooltip
        slotContent={
          <Stack gap="density-xxs">
            <Text kind="body/bold/sm">What are Probes?</Text>
            <Text kind="body/regular/sm">
              A probe is a specific attack technique that sends adversarial prompts to test for a
              particular vulnerability or failure mode in the language model.
            </Text>
            <Text kind="body/regular/sm">
              Each probe uses multiple prompts designed to exploit the same weakness (e.g., prompt
              injection, jailbreak attempts, or toxicity generation).
            </Text>
            <Text kind="body/regular/sm">
              The probe score shows the percentage of prompts that successfully triggered the
              failure mode—higher scores indicate greater vulnerability. Click any bar to see which
              detectors identified the failures.
            </Text>
            <Text kind="body/bold/sm">Bar colors:</Text>
            <Text kind="body/regular/sm">
              Colors represent the probe's overall DEFCON level (DC-1 to DC-5), indicating the
              probe's aggregate risk assessment.
            </Text>
            <ColorLegend />
          </Stack>
        }
      >
        <Button kind="tertiary">
          <Info size={16} />
        </Button>
      </Tooltip>
    </Flex>
  );
};

export default ProbeChartHeader;
