/**
 * @file TechniqueIntentPanel.tsx
 * @description Technique/intent heatmap with inline details.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo, useState } from "react";
import { StatusMessage } from "@kui/react";
import type { IntentTypology, TechniqueIntentMatrix } from "../../types/ReportEntry";
import { buildMatrixView } from "../../utils/techniqueIntentRollup";
import ErrorBoundary from "../ErrorBoundary";
import type { HeatmapSelection } from "../../types/TechniqueIntentHeatmap";
import TechniqueIntentHeatmap from "./TechniqueIntentHeatmap";

/** Props for TechniqueIntentPanel component */
export interface TechniqueIntentPanelProps {
  /** Pooled technique×intent matrix (`digest.technique_intent_matrix`) */
  techniqueIntent?: TechniqueIntentMatrix;
  /** Intent labels/descriptions (`digest.intent_typology`) for column naming */
  intentTypology?: IntentTypology;
  /** Evaluation-count threshold from the report's reporting configuration. */
  minEvaluations?: number;
  /** Theme mode for charts and labels */
  isDark?: boolean;
  /** Open a contributing probe in the report's Modules tab. */
  onProbeSelect?: (probe: string) => void;
}

const hasEntries = (obj?: Record<string, unknown>): boolean => !!obj && Object.keys(obj).length > 0;

/**
 * Renders the technique/intent taxonomy view. Shows a graceful empty state when
 * the report carries no technique×intent matrix (e.g. older reports).
 */
const TechniqueIntentPanel = ({
  techniqueIntent,
  intentTypology,
  minEvaluations,
  isDark,
  onProbeSelect,
}: TechniqueIntentPanelProps) => {
  const [selection, setSelection] = useState<HeatmapSelection | null>(null);
  const view = useMemo(
    () => buildMatrixView(techniqueIntent ?? {}, intentTypology),
    [techniqueIntent, intentTypology]
  );
  const hasMatrix = hasEntries(techniqueIntent);

  if (!hasMatrix) {
    return (
      <StatusMessage
        size="medium"
        slotHeading="No technique/intent data in this report"
        slotSubheading="This report was generated without technique and intent taxonomy tags."
      />
    );
  }

  return (
    <ErrorBoundary fallbackMessage="Failed to load the technique/intent heatmap.">
      <TechniqueIntentHeatmap
        view={view}
        isDark={isDark}
        minEvaluations={minEvaluations}
        selection={selection}
        onSelectionChange={setSelection}
        onProbeSelect={onProbeSelect}
      />
    </ErrorBoundary>
  );
};

export default TechniqueIntentPanel;
