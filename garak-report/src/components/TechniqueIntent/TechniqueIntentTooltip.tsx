/**
 * @file TechniqueIntentTooltip.tsx
 * @description Compact pairing preview for the heatmap's ECharts tooltip.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Badge, Divider, Flex, Stack, Text } from "@kui/react";
import { HEATMAP_MIN_EVALUATIONS } from "../../constants";
import TechniqueIntentTooltipScore from "./TechniqueIntentTooltipScore";
import type { MatrixView } from "../../utils/techniqueIntentRollup";

interface TechniqueIntentTooltipProps {
  view: MatrixView;
  technique: string;
  intent: string;
  minEvaluations?: number;
}

/** Previews evaluated outcomes without confusing evaluations with distinct prompts. */
const TechniqueIntentTooltip = ({
  view,
  technique,
  intent,
  minEvaluations = HEATMAP_MIN_EVALUATIONS,
}: TechniqueIntentTooltipProps) => {
  const cell = view.cell(technique, intent);
  const description = view.colDescription(intent);

  return (
    <Stack gap="density-lg" role="tooltip" aria-label="Pairing preview">
      <Stack gap="density-sm">
        <Stack gap="density-xxs">
          <Text kind="label/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
            Technique
          </Text>
          <Text kind="body/bold/md">{view.rowLabel(technique)}</Text>
        </Stack>
        <Stack gap="density-xxs">
          <Text kind="label/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
            Intent
          </Text>
          <Text kind="body/bold/md">{view.colLabel(intent)}</Text>
        </Stack>
      </Stack>
      <Divider />
      {cell ? (
        <Stack gap="density-sm">
          <TechniqueIntentTooltipScore score={cell.score} label="Observed pass rate" />
          <Text kind="body/bold/md">
            {cell.passed.toLocaleString()} of {cell.nEvaluations.toLocaleString()} detector{" "}
            {cell.nEvaluations === 1 ? "evaluation" : "evaluations"} passed
          </Text>
          {cell.nEvaluations < minEvaluations && (
            <Flex align="center" gap="density-sm" wrap="wrap">
              <Badge color="gray" kind="outline">
                Low evaluation count
              </Badge>
              <Text kind="body/regular/sm">n &lt; {minEvaluations.toLocaleString()}</Text>
            </Flex>
          )}
          <Text kind="body/regular/sm">
            {(cell.nEvaluations - cell.passed).toLocaleString()} failed
            {cell.nones > 0 &&
              ` · ${cell.nones.toLocaleString()} undetermined (excluded from pass rate)`}
          </Text>
        </Stack>
      ) : (
        <Stack gap="density-xs">
          <Text kind="body/bold/md">Not evaluated</Text>
          <Text kind="body/regular/sm">No results for this pairing.</Text>
        </Stack>
      )}
      {description && (
        <Text
          kind="body/regular/sm"
          style={{
            display: "-webkit-box",
            WebkitLineClamp: 3,
            WebkitBoxOrient: "vertical",
            overflow: "hidden",
          }}
        >
          {description}
        </Text>
      )}
      {cell && (
        <>
          <Divider />
          <Text kind="body/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
            Select cell for full details below.
          </Text>
        </>
      )}
    </Stack>
  );
};

export default TechniqueIntentTooltip;
