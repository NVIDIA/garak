/**
 * @file MetadataSection.tsx
 * @description Tabbed display component for report metadata and payload information.
 *              Shows overview data and expandable payload details.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { ReportEntry } from "../types/ReportEntry";
import { usePayloadParser } from "../hooks/usePayloadParser";
import { Tabs, Text, Stack, Flex, Badge } from "@kui/react";

/** Props for MetadataSection component */
type MetadataSectionProps = {
  meta: ReportEntry["meta"];
};

/**
 * Displays report metadata in a tabbed interface.
 * Includes overview tab with run details and optional payloads tab.
 *
 * @param props - Component props
 * @param props.meta - Report metadata object
 * @returns Tabbed metadata display with overview and payloads
 */
const MetadataSection = ({ meta }: MetadataSectionProps) => {
  const uniquePayloads = usePayloadParser(meta.payloads);

  // Split probespec by comma for list display
  const probesList = meta.probespec ? meta.probespec.split(",").map(s => s.trim()) : [];

  const tabs = [
    {
      value: "overview",
      children: "Overview",
      slotContent: (
        <Stack gap="density-xl">
          {meta.run_uuid && (
            <Flex gap="density-xs" align="baseline">
              <Text kind="label/bold/sm">Run UUID:</Text>
              <Text kind="mono/sm">{meta.run_uuid}</Text>
            </Flex>
          )}
          {meta.reportfile && (
            <Stack gap="density-xxs">
              <Text kind="label/bold/sm">Report File:</Text>
              <Text kind="mono/sm">{meta.reportfile}</Text>
            </Stack>
          )}
          {meta.report_digest_time && (
            <Flex gap="density-xs" align="baseline">
              <Text kind="label/bold/sm">Analysis Completed:</Text>
              <Text kind="body/regular/sm">
                {new Date(meta.report_digest_time).toLocaleString()}
              </Text>
            </Flex>
          )}
          {meta.group_aggregation_function && (
            <Flex gap="density-xs" align="baseline">
              <Text kind="label/bold/sm">Score Aggregation:</Text>
              <Text kind="body/regular/sm">{meta.group_aggregation_function}</Text>
            </Flex>
          )}
          {probesList.length > 0 && (
            <Stack gap="density-xs">
              <Text kind="label/bold/sm">Probes:</Text>
              <Stack gap="density-xs">
                {probesList.map((probe, idx) => (
                  <Text key={idx} kind="body/regular/sm">
                    {probe}
                  </Text>
                ))}
              </Stack>
            </Stack>
          )}
        </Stack>
      ),
    },
  ];

  // Add payloads tab if there are payloads
  if (uniquePayloads.length > 0) {
    tabs.push({
      value: "payloads",
      children: `Payloads (${uniquePayloads.length})`,
      slotContent: (
        <Stack gap="density-md">
          {uniquePayloads.map((payload, idx) => (
            <Stack key={idx} gap="density-xs" padding="density-md">
              <Flex justify="between" align="center">
                <Text kind="label/bold/md">{payload.payload_name}</Text>
                <Badge color="green" kind="outline">
                  {payload.entries} entries
                </Badge>
              </Flex>
              <Flex gap="density-md">
                {payload.filesize > 0 && (
                  <Flex gap="density-xs" align="baseline">
                    <Text kind="label/bold/sm">Size:</Text>
                    <Text kind="body/regular/sm">{(payload.filesize / 1024).toFixed(2)} KB</Text>
                  </Flex>
                )}
                {payload.mtime && (
                  <Flex gap="density-xs" align="baseline">
                    <Text kind="label/bold/sm">Modified:</Text>
                    <Text kind="body/regular/sm">
                      {new Date(parseFloat(payload.mtime) * 1000).toLocaleString()}
                    </Text>
                  </Flex>
                )}
              </Flex>
              <Stack gap="density-xxs">
                <Text kind="label/bold/sm">Path:</Text>
                <Text kind="mono/sm" style={{ wordBreak: "break-all" }}>
                  {payload.payload_path}
                </Text>
              </Stack>
            </Stack>
          ))}
        </Stack>
      ),
    });
  }

  return <Tabs items={tabs} />;
};

export default MetadataSection;
