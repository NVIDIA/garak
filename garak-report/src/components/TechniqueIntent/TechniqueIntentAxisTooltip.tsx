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

/** Counts belong to the weakest pairing; other pairings may reuse its evidence. */
const TechniqueIntentAxisTooltip = ({ group, axis, total }: TechniqueIntentAxisTooltipProps) => {
  const worst = group.cells.find(item => item.cell.score != null);
  const tied = worst
    ? group.cells.filter(item => item.cell.score === worst.cell.score).length - 1
    : 0;
  const undetermined = group.cells.filter(item => item.cell.score == null).length;
  return (
    <Stack
      gap="density-lg"
      role="tooltip"
      aria-label={`${axis === "technique" ? "Technique" : "Intent"} preview`}
    >
      <Stack gap="density-xs">
        <Text kind="label/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
          {axis === "technique" ? "Technique" : "Intent"}
        </Text>
        <Text kind="body/bold/md">{group.label}</Text>
        {axis === "intent" && group.label !== group.key && (
          <Flex>
            <Badge color="gray" kind="outline">
              {group.key}
            </Badge>
          </Flex>
        )}
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
      <Stack
        gap="density-sm"
        role="group"
        aria-label={worst ? "Weakest pairing" : "Pairing results"}
      >
        <Text kind="label/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
          {worst ? "Weakest pairing" : "Pairing results"}
        </Text>
        {worst && worst.cell.score != null ? (
          <>
            <Text kind="body/bold/md">{worst.otherLabel}</Text>
            <TechniqueIntentTooltipScore score={worst.cell.score} />
            <Text kind="body/regular/sm">
              {worst.cell.passed.toLocaleString()} of {worst.cell.nEvaluations.toLocaleString()}{" "}
              detector evaluations passed
            </Text>
            <Text kind="body/regular/sm">
              {(worst.cell.nEvaluations - worst.cell.passed).toLocaleString()} failed
              {worst.cell.nones > 0 &&
                ` · ${worst.cell.nones.toLocaleString()} undetermined (excluded from pass rate)`}
            </Text>
            {tied > 0 && (
              <Text kind="body/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
                {tied} other {tied === 1 ? "pairing" : "pairings"} at this pass rate.
              </Text>
            )}
          </>
        ) : (
          <Text kind="body/bold/md">No determinate results</Text>
        )}
      </Stack>
      <Divider />
      <Stack gap="density-sm" role="group" aria-label="Across tested pairings">
        <Flex align="start" justify="between" gap="density-md">
          <Text kind="body/regular/sm">
            {axis === "technique" ? "Intents" : "Techniques"} with results
          </Text>
          <Text kind="body/bold/sm" style={{ whiteSpace: "nowrap" }}>
            {group.cells.length} of {total}
          </Text>
        </Flex>
        {undetermined > 0 && (
          <Text kind="body/regular/sm">
            {undetermined} {undetermined === 1 ? "pairing" : "pairings"} undetermined
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
