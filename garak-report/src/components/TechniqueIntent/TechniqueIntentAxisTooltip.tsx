/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Badge, Divider, Flex, Stack, Text } from "@kui/react";
import type { AxisGroup, TaxonomyAxis } from "../../utils/techniqueIntentRollup";
import TechniqueIntentTooltipScore from "./TechniqueIntentTooltipScore";

interface TechniqueIntentAxisTooltipProps {
  group: AxisGroup;
  axis: TaxonomyAxis;
  total: number;
}

/** Summarises an axis using the same worst-pairing score as the existing lists. */
const TechniqueIntentAxisTooltip = ({ group, axis, total }: TechniqueIntentAxisTooltipProps) => {
  const worst = group.cells[0];
  const tied = group.cells.filter(item => item.cell.score === group.score).length - 1;
  const failed = group.cells.reduce(
    (sum, item) => sum + item.cell.nEvaluations - item.cell.passed,
    0
  );
  const nones = group.cells.reduce((sum, item) => sum + item.cell.nones, 0);

  const title =
    axis === "intent" && group.label.startsWith(`${group.key} - `)
      ? group.label.slice(group.key.length + 3)
      : group.label;

  return (
    <Stack
      gap="density-lg"
      role="tooltip"
      aria-label={`${axis === "technique" ? "Technique" : "Intent"} preview`}
    >
      <Stack gap="density-xs">
        <Flex align="center" gap="density-sm">
          <Text kind="label/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
            {axis === "technique" ? "Technique" : "Intent"}
          </Text>
          {axis === "intent" && (
            <Badge color="gray" kind="outline">
              {group.key}
            </Badge>
          )}
        </Flex>
        {(axis === "technique" || title !== group.key) && <Text kind="body/bold/md">{title}</Text>}
        {group.description && (
          <Text
            kind="body/regular/sm"
            style={{
              color: "var(--text-color-secondary)",
              display: "-webkit-box",
              WebkitLineClamp: 3,
              WebkitBoxOrient: "vertical",
              overflow: "hidden",
            }}
          >
            {group.description}
          </Text>
        )}
      </Stack>
      <Divider />
      <Stack gap="density-sm" role="group" aria-label="Weakest pairing">
        <Text kind="label/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
          Weakest pairing
        </Text>
        {worst && <Text kind="body/bold/md">{worst.otherLabel}</Text>}
        <TechniqueIntentTooltipScore score={group.score} />
        {tied > 0 && (
          <Text kind="body/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
            {tied} other {tied === 1 ? "pairing" : "pairings"} at this pass rate.
          </Text>
        )}
      </Stack>
      <Divider />
      <Stack gap="density-sm" role="group" aria-label="Across tested pairings">
        <Text kind="label/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
          Across tested pairings
        </Text>
        <Flex align="start" justify="between" gap="density-md">
          <Text kind="body/regular/sm">
            {axis === "technique" ? "Intents" : "Techniques"} evaluated
          </Text>
          <Text kind="body/bold/sm" style={{ whiteSpace: "nowrap" }}>
            {group.cells.length} of {total}
          </Text>
        </Flex>
        <Flex align="start" justify="between" gap="density-md">
          <Text kind="body/regular/sm">Failed evaluations</Text>
          <Text kind="body/bold/sm" style={{ whiteSpace: "nowrap" }}>
            {failed.toLocaleString()} of {group.nEvaluations.toLocaleString()}
          </Text>
        </Flex>
        {nones > 0 && (
          <Text kind="body/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
            {nones.toLocaleString()} undetermined (excluded from pass rate)
          </Text>
        )}
      </Stack>
      <Text kind="body/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
        Click {axis === "technique" ? "row" : "column"} to inspect details.
      </Text>
    </Stack>
  );
};

export default TechniqueIntentAxisTooltip;
