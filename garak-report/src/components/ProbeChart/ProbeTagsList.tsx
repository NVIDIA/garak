/**
 * @file ProbeTagsList.tsx
 * @description Displays taxonomy tags associated with probes in the current module.
 * @module components/ProbeChart
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Badge, Button, Flex, Stack, Text, Tooltip } from "@kui/react";
import { Info } from "lucide-react";

/** Props for ProbeTagsList component */
interface ProbeTagsListProps {
  tags: string[];
}

/**
 * Displays a list of taxonomy tags with explanatory tooltip.
 * Tags are shown as gray outline badges in a wrapped flex layout.
 *
 * @param props - Component props
 * @param props.tags - Array of tag strings to display
 * @returns Tag list with info tooltip, or null if no tags
 */
const ProbeTagsList = ({ tags }: ProbeTagsListProps) => {
  if (tags.length === 0) return null;

  return (
    <Stack gap="density-xs" paddingTop="density-sm" paddingBottom="density-md">
      <Flex align="center" gap="density-xxs">
        <Text kind="label/bold/sm">Tags</Text>
        <Tooltip
          slotContent={
            <Stack gap="density-xxs">
              <Text kind="body/regular/sm">
                Tags categorize probes using industry-standard taxonomies and frameworks.
              </Text>
              <Text kind="body/bold/sm">Common tag prefixes:</Text>
              <Text kind="body/regular/sm">
                • <strong>owasp:</strong> OWASP LLM Top 10 vulnerabilities
              </Text>
              <Text kind="body/regular/sm">
                • <strong>avid-effect:</strong> AVID AI Vulnerability taxonomy (security, ethics,
                performance)
              </Text>
              <Text kind="body/regular/sm">
                • <strong>risk-cards:</strong> Language Model Risk Cards framework
              </Text>
              <Text kind="body/regular/sm">
                • <strong>quality:</strong> Quality assessment categories
              </Text>
              <Text kind="body/regular/sm">
                • <strong>payload:</strong> Type of attack payload used
              </Text>
            </Stack>
          }
        >
          <Button kind="tertiary">
            <Info size={14} />
          </Button>
        </Tooltip>
      </Flex>
      <Flex gap="density-xs" wrap="wrap">
        {tags.map((tag, idx) => (
          <Badge key={idx} color="gray" kind="outline">
            <Text kind="label/regular/xs">{tag}</Text>
          </Badge>
        ))}
      </Flex>
    </Stack>
  );
};

export default ProbeTagsList;
