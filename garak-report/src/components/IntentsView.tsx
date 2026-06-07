/**
 * @file IntentsView.tsx
 * @description Intent-centric T&I view. Rows are intents, columns are the
 *              `demon:*` techniques that exercised them; each cell is the
 *              pooled pass rate. Mirrors the DetectorsView/ProbesChart panel
 *              structure.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Panel, Stack, Flex, Text, Badge } from "@kui/react";
import type { IntentsViewProps } from "../types/TechniqueIntent";
import useTechniqueIntent from "../hooks/useTechniqueIntent";
import useSeverityColor from "../hooks/useSeverityColor";
import TechniqueIntentMatrix from "./TechniqueIntentMatrix";

/**
 * Panel showing the technique×intent matrix from an intent-first perspective.
 *
 * @param props.matrix - The `technique_intent_matrix` digest field
 * @returns Intent analysis panel
 */
const IntentsView = ({ matrix }: IntentsViewProps) => {
  const { intents, techniques } = useTechniqueIntent(matrix);
  const { getSeverityColorByLevel } = useSeverityColor();

  const techniqueNames = techniques.map((t) => t.technique_name);
  const cells = Object.fromEntries(intents.map((i) => [i.intent_name, i.cells]));

  return (
    <Panel>
      <Stack gap="density-xl">
        <Stack gap="density-md">
          <Flex gap="density-md" align="center">
            <Text kind="title/lg">Intents</Text>
            <Badge color="gray" kind="outline">
              {intents.length} intent{intents.length === 1 ? "" : "s"}
            </Badge>
            <Badge color="gray" kind="outline">
              {techniqueNames.length} technique{techniqueNames.length === 1 ? "" : "s"}
            </Badge>
          </Flex>
          <Text kind="body/regular/md" style={{ color: "var(--color-tk-400)" }}>
            Pass rate per intent across the techniques used to elicit it. Higher
            is safer; blank cells were not exercised.
          </Text>
        </Stack>

        <TechniqueIntentMatrix
          rowLabels={intents.map((i) => i.intent_name)}
          colLabels={techniqueNames}
          cells={cells}
          getColor={getSeverityColorByLevel}
          rowAxisLabel="Intent"
          colAxisLabel="Technique"
        />
      </Stack>
    </Panel>
  );
};

export default IntentsView;
