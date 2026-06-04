/**
 * @file TechniqueIntentSection.tsx
 * @description Report section presenting the technique & intent (T&I) views in
 *              a collapsible accordion holding a tabbed panel. Hidden entirely
 *              when the report predates the `technique_intent_matrix` digest
 *              field. Implements garak#1705.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useState } from "react";
import { Accordion, Stack, Tabs, Text } from "@kui/react";
import type { TechniqueIntentMatrix } from "../types/TechniqueIntent";
import TechniquesView from "./TechniquesView";
import IntentsView from "./IntentsView";

/** Accordion item value for the single T&I panel. */
const PANEL_VALUE = "technique-intent";

/** Props for the T&I report section. */
export type TechniqueIntentSectionProps = {
  /** The `technique_intent_matrix` digest field, if present */
  matrix?: TechniqueIntentMatrix;
  isDark?: boolean;
};

/**
 * Collapsible Technique/Intent section. Wraps the tabbed T&I views in an
 * accordion (consistent with the module list) and renders nothing for reports
 * without the matrix (older garak versions) so the page degrades gracefully.
 * Expanded by default so the overview is visible without an extra click.
 */
const TechniqueIntentSection = ({ matrix, isDark }: TechniqueIntentSectionProps) => {
  const [tab, setTab] = useState<string>("techniques");
  const [open, setOpen] = useState<string>(PANEL_VALUE);

  if (!matrix || Object.keys(matrix).length === 0) return null;

  return (
    <Accordion
      value={open}
      onValueChange={(value) => setOpen(value as string)}
      items={[
        {
          value: PANEL_VALUE,
          slotTrigger: <Text kind="label/bold/2xl">Technique &amp; Intent</Text>,
          slotContent: (
            <Stack gap="density-md">
              <Tabs
                value={tab}
                onValueChange={setTab}
                items={[
                  { value: "techniques", children: "By technique" },
                  { value: "intents", children: "By intent" },
                ]}
              />
              {tab === "techniques" ? (
                <TechniquesView matrix={matrix} isDark={isDark} />
              ) : (
                <IntentsView matrix={matrix} isDark={isDark} />
              )}
            </Stack>
          ),
        },
      ]}
    />
  );
};

export default TechniqueIntentSection;
