/**
 * @file TechniqueIntentSection.tsx
 * @description Report section presenting the technique & intent (T&I) views in
 *              a tabbed panel. Hidden entirely when the report predates the
 *              `technique_intent_matrix` digest field. Implements garak#1705.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useState } from "react";
import { Stack, Tabs, Text } from "@kui/react";
import type { TechniqueIntentMatrix } from "../types/TechniqueIntent";
import TechniquesView from "./TechniquesView";
import IntentsView from "./IntentsView";

/** Props for the T&I report section. */
export type TechniqueIntentSectionProps = {
  /** The `technique_intent_matrix` digest field, if present */
  matrix?: TechniqueIntentMatrix;
  isDark?: boolean;
};

/**
 * Tabbed Technique/Intent section. Renders nothing for reports without the
 * matrix (older garak versions) so the page degrades gracefully.
 */
const TechniqueIntentSection = ({ matrix, isDark }: TechniqueIntentSectionProps) => {
  const [tab, setTab] = useState<string>("techniques");

  if (!matrix || Object.keys(matrix).length === 0) return null;

  return (
    <Stack gap="density-md" style={{ padding: "var(--density-lg)" }}>
      <Text kind="title/md">Technique &amp; Intent</Text>
      <Tabs
        value={tab}
        onValueChange={setTab}
        items={[
          { value: "techniques", label: "By technique" },
          { value: "intents", label: "By intent" },
        ]}
      />
      {tab === "techniques" ? (
        <TechniquesView matrix={matrix} isDark={isDark} />
      ) : (
        <IntentsView matrix={matrix} isDark={isDark} />
      )}
    </Stack>
  );
};

export default TechniqueIntentSection;
