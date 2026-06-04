/**
 * @file TechniquesView.tsx
 * @description Technique-centric T&I view. Rows are `demon:*` techniques,
 *              columns are intents; each cell is the pooled pass rate.
 *              Mirrors the DetectorsView/ProbesChart panel structure.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Panel, Stack, Flex, Text, Badge } from "@kui/react";
import type { TechniquesViewProps } from "../types/TechniqueIntent";
import useTechniqueIntent from "../hooks/useTechniqueIntent";
import useSeverityColor from "../hooks/useSeverityColor";
import TechniqueIntentMatrix from "./TechniqueIntentMatrix";

/**
 * Panel showing the technique×intent matrix from a technique-first perspective.
 *
 * @param props.matrix - The `technique_intent_matrix` digest field
 * @returns Technique analysis panel
 */
const TechniquesView = ({ matrix }: TechniquesViewProps) => {
  const { techniques, intentNames } = useTechniqueIntent(matrix);
  const { getSeverityColorByLevel } = useSeverityColor();

  const cells = Object.fromEntries(techniques.map((t) => [t.technique_name, t.cells]));

  return (
    <Panel>
      <Stack gap="density-xl">
        <Stack gap="density-md">
          <Flex gap="density-md" align="center">
            <Text kind="title/lg">Techniques</Text>
            <Badge color="gray" kind="outline">
              {techniques.length} technique{techniques.length === 1 ? "" : "s"}
            </Badge>
            <Badge color="gray" kind="outline">
              {intentNames.length} intent{intentNames.length === 1 ? "" : "s"}
            </Badge>
          </Flex>
          <Text kind="body/regular/md" style={{ color: "var(--color-tk-400)" }}>
            Pass rate per attack technique across the intents it was exercised
            against. Higher is safer; blank cells were not exercised.
          </Text>
        </Stack>

        <TechniqueIntentMatrix
          rowLabels={techniques.map((t) => t.technique_name)}
          colLabels={intentNames}
          cells={cells}
          getColor={getSeverityColorByLevel}
          rowAxisLabel="Technique"
          colAxisLabel="Intent"
        />
      </Stack>
    </Panel>
  );
};

export default TechniquesView;
