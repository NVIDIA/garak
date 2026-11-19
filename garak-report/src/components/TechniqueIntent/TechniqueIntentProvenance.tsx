/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Flex, Stack, Tag, Text } from "@kui/react";
import type { ProbeDetectorPair } from "../../types/ReportEntry";

/** Open each contributing probe once in the report's existing module view. */
const TechniqueIntentProvenance = ({
  pairs,
  onProbeSelect,
}: {
  pairs: ProbeDetectorPair[];
  onProbeSelect?: (probe: string) => void;
}) => (
  <Stack gap="density-sm">
    <Text kind="label/bold/md">Probes used</Text>
    <Flex gap="density-xs" wrap="wrap">
      {[...new Set(pairs.map(([probe]) => probe))].map(probe => (
        <Tag
          key={probe}
          color="gray"
          kind="outline"
          density="compact"
          className="max-w-full whitespace-normal text-left"
          readOnly={!onProbeSelect}
          aria-label={`Open ${probe} in report`}
          onClick={() => onProbeSelect?.(probe)}
        >
          <Text kind="mono/sm" style={{ overflowWrap: "anywhere" }}>
            {probe}
          </Text>
        </Tag>
      ))}
    </Flex>
  </Stack>
);

export default TechniqueIntentProvenance;
