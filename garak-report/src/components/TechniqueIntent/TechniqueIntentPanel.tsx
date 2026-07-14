/**
 * @file TechniqueIntentPanel.tsx
 * @description Orchestrates the technique/intent taxonomy visualizations:
 *              a technique x intent heatmap plus 1D breakdowns for each axis.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo, useState } from "react";
import { Flex, Grid, StatusMessage } from "@kui/react";
import type {
  TaxonomyScore,
  TaxonomyScoreMap,
  TechniqueIntentMatrix,
} from "../../types/ReportEntry";
import { aggregationLabel } from "../../constants";
import ErrorBoundary from "../ErrorBoundary";
import TechniqueIntentHeatmap from "./TechniqueIntentHeatmap";
import TaxonomyBreakdownChart from "./TaxonomyBreakdownChart";
import TechniqueIntentDetailPanel from "./TechniqueIntentDetailPanel";
import type { TaxonomyDetail } from "./types";

/** Props for TechniqueIntentPanel component */
export interface TechniqueIntentPanelProps {
  /** Flat intent -> score map (`digest.intent`) */
  intent?: TaxonomyScoreMap;
  /** Flat technique -> score map (`digest.technique`) */
  technique?: TaxonomyScoreMap;
  /** Nested technique -> intent -> score matrix (`digest.technique_intent`) */
  techniqueIntent?: TechniqueIntentMatrix;
  /** Theme mode for styling */
  isDark?: boolean;
}

const hasEntries = (obj?: Record<string, unknown>): boolean =>
  !!obj && Object.keys(obj).length > 0;

const SectionHeading = ({ title, subtitle }: { title: string; subtitle?: string }) => (
  <div>
    <h2 className="text-lg font-semibold">{title}</h2>
    {subtitle && <p className="text-sm opacity-70">{subtitle}</p>}
  </div>
);

/** Reads the `aggregation` key from the first available cell of any TI source. */
const firstAggregation = (
  matrix?: TechniqueIntentMatrix,
  technique?: TaxonomyScoreMap,
  intent?: TaxonomyScoreMap,
): string | undefined => {
  const fromMap = (m?: TaxonomyScoreMap): TaxonomyScore | undefined =>
    m ? Object.values(m)[0] : undefined;
  const fromMatrix = (m?: TechniqueIntentMatrix): TaxonomyScore | undefined => {
    if (!m) return undefined;
    const row = Object.values(m)[0];
    return row ? Object.values(row)[0] : undefined;
  };
  return (
    fromMatrix(matrix)?.aggregation ??
    fromMap(technique)?.aggregation ??
    fromMap(intent)?.aggregation
  );
};

/**
 * Renders the technique/intent taxonomy view. Shows a graceful empty state when
 * none of the three sections are present (e.g. older reports).
 */
const TechniqueIntentPanel = ({
  intent,
  technique,
  techniqueIntent,
  isDark,
}: TechniqueIntentPanelProps) => {
  const [selected, setSelected] = useState<TaxonomyDetail | null>(null);

  const hasMatrix = hasEntries(techniqueIntent);
  const hasTechnique = hasEntries(technique);
  const hasIntent = hasEntries(intent);

  const aggLabel = useMemo(
    () => aggregationLabel(firstAggregation(techniqueIntent, technique, intent)),
    [techniqueIntent, technique, intent],
  );

  if (!hasMatrix && !hasTechnique && !hasIntent) {
    return (
      <StatusMessage
        size="medium"
        slotHeading="No technique/intent data in this report"
        slotSubheading="This report was generated without technique and intent taxonomy tags."
      />
    );
  }

  return (
    <Flex direction="col" gap="6" style={{ width: "100%" }}>
      {hasMatrix && (
        <Flex direction="col" gap="2">
          <SectionHeading
            title="Technique × Intent"
            subtitle={`Each cell is the ${aggLabel} for that technique (row) × intent (column). Lower (red) = more vulnerable. Click a cell to see the failing attempts.`}
          />
          <ErrorBoundary fallbackMessage="Failed to load the technique/intent heatmap.">
            <TechniqueIntentHeatmap
              matrix={techniqueIntent!}
              isDark={isDark}
              onSelect={setSelected}
            />
          </ErrorBoundary>
        </Flex>
      )}

      {(hasTechnique || hasIntent) && (
        <Grid cols={{ base: 1, lg: 2 }} gap="density-lg">
          {hasTechnique && (
            <Flex direction="col" gap="2">
              <SectionHeading
                title="By technique"
                subtitle={`Adversarial method, scored as the ${aggLabel} pooled across its intents (worst first). May read lower than individual cells above.`}
              />
              <ErrorBoundary fallbackMessage="Failed to load the technique breakdown.">
                <TaxonomyBreakdownChart
                  data={technique!}
                  kind="technique"
                  isDark={isDark}
                  onSelect={setSelected}
                  aggregationLabel={aggLabel}
                />
              </ErrorBoundary>
            </Flex>
          )}
          {hasIntent && (
            <Flex direction="col" gap="2">
              <SectionHeading
                title="By intent"
                subtitle={`Targeted failure mode, scored as the ${aggLabel} pooled across techniques (worst first).`}
              />
              <ErrorBoundary fallbackMessage="Failed to load the intent breakdown.">
                <TaxonomyBreakdownChart
                  data={intent!}
                  kind="intent"
                  isDark={isDark}
                  onSelect={setSelected}
                  aggregationLabel={aggLabel}
                />
              </ErrorBoundary>
            </Flex>
          )}
        </Grid>
      )}

      <TechniqueIntentDetailPanel detail={selected} onClose={() => setSelected(null)} />
    </Flex>
  );
};

export default TechniqueIntentPanel;
