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
import { Flex, PageHeader, StatusMessage, Text, SegmentedControl } from "@kui/react";
import type {
  TaxonomyScore,
  TaxonomyScoreMap,
  TechniqueIntentMatrix,
} from "../../types/ReportEntry";
import { aggregationLabel } from "../../constants";
import {
  buildMatrixView,
  restrictMapToLevelKeys,
  type MatrixLevel,
} from "../../utils/techniqueIntentRollup";
import ErrorBoundary from "../ErrorBoundary";
import TechniqueIntentHeatmap from "./TechniqueIntentHeatmap";
import TaxonomyBreakdownChart from "./TaxonomyBreakdownChart";
import TechniqueIntentDetailPanel from "./TechniqueIntentDetailPanel";
import type { TaxonomyDetail, TaxonomyHover } from "./types";

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
  <PageHeader slotHeading={title} slotDescription={subtitle} style={{ maxWidth: "75%" }} />
);

const LEVEL_ITEMS = [
  { value: "grouped", children: "Grouped" },
  { value: "leaf", children: "All leaves" },
];

/**
 * Two-position segmented control to switch the whole view between the grouped
 * (worst-case roll-up) and full-leaf levels. Lives in the panel header because
 * it reshapes every chart (both breakdown bars and the matrix), not just one.
 */
const LevelToggle = ({
  level,
  onChange,
}: {
  level: MatrixLevel;
  onChange: (level: MatrixLevel) => void;
}) => (
  <SegmentedControl
    size="small"
    value={level}
    onValueChange={value => onChange(value as MatrixLevel)}
    items={LEVEL_ITEMS}
  />
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
  const [level, setLevel] = useState<MatrixLevel>("grouped");
  // Coordinated-hover selection, shared across the two breakdown bars and the
  // heatmap so hovering one view highlights the matching row/column elsewhere.
  const [hovered, setHovered] = useState<TaxonomyHover | null>(null);

  const viewGrouped = useMemo(
    () => buildMatrixView(techniqueIntent ?? {}, "grouped"),
    [techniqueIntent],
  );
  const viewLeaf = useMemo(() => buildMatrixView(techniqueIntent ?? {}, "leaf"), [techniqueIntent]);
  // Only offer the toggle when grouping actually collapses the grid; otherwise
  // the two levels are identical and a control would just add noise.
  const reducible = viewGrouped.reducible;
  const activeLevel: MatrixLevel = reducible ? level : "leaf";
  const activeView = activeLevel === "grouped" ? viewGrouped : viewLeaf;

  const hasMatrix = hasEntries(techniqueIntent);
  const hasTechnique = hasEntries(technique);
  const hasIntent = hasEntries(intent);

  // Keep the 1D bars on the same categories as the heatmap. The marginal maps
  // can include techniques/intents that never appear as a technique×intent
  // pair, so when a matrix is present we restrict each marginal to the rows/
  // columns the heatmap actually shows. Without a matrix the marginal is shown
  // as-is.
  const techniqueBars = useMemo(() => {
    if (!technique) return undefined;
    return hasMatrix
      ? restrictMapToLevelKeys(technique, "technique", activeLevel, new Set(activeView.rows))
      : technique;
  }, [technique, hasMatrix, activeLevel, activeView]);
  const intentBars = useMemo(() => {
    if (!intent) return undefined;
    return hasMatrix
      ? restrictMapToLevelKeys(intent, "intent", activeLevel, new Set(activeView.cols))
      : intent;
  }, [intent, hasMatrix, activeLevel, activeView]);

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
    <Flex direction="col" gap="density-2xl" style={{ width: "100%" }}>
      {/* Panel-level control row, mirroring the Modules tab's filter bar. The
          detail-level toggle governs every chart below, so it sits here as a
          labeled control rather than inside the heatmap section. The tab label
          already names the view, so we don't repeat a title. */}
      {reducible && (
        <Flex gap="density-sm" align="center" wrap="wrap">
          <Text kind="label/bold/md">Detail level:</Text>
          <LevelToggle level={activeLevel} onChange={setLevel} />
          <Text kind="label/regular/sm" className="opacity-60">
            applies to every chart below
          </Text>
        </Flex>
      )}

      {/* 1D breakdowns: now compact vertical-bar charts, so they sit side-by-side
          on wide screens (auto-stacking when the column gets too narrow) instead
          of eating two full-height rows. */}
      {(hasTechnique || hasIntent) && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))",
            gap: "2rem",
          }}
        >
          {hasTechnique && (
            <Flex direction="col" gap="density-md">
              <SectionHeading
                title="By technique"
                subtitle={`Adversarial method, scored as the ${aggLabel} pooled across its intents (worst first). May read lower than individual cells in the matrix below.`}
              />
              <ErrorBoundary fallbackMessage="Failed to load the technique breakdown.">
                <TaxonomyBreakdownChart
                  data={techniqueBars!}
                  kind="technique"
                  isDark={isDark}
                  onSelect={setSelected}
                  aggregationLabel={aggLabel}
                  level={activeLevel}
                  hover={hovered}
                  onHover={setHovered}
                />
              </ErrorBoundary>
            </Flex>
          )}
          {hasIntent && (
            <Flex direction="col" gap="density-md">
              <SectionHeading
                title="By intent"
                subtitle={`Targeted failure mode, scored as the ${aggLabel} pooled across techniques (worst first).`}
              />
              <ErrorBoundary fallbackMessage="Failed to load the intent breakdown.">
                <TaxonomyBreakdownChart
                  data={intentBars!}
                  kind="intent"
                  isDark={isDark}
                  onSelect={setSelected}
                  aggregationLabel={aggLabel}
                  level={activeLevel}
                  hover={hovered}
                  onHover={setHovered}
                />
              </ErrorBoundary>
            </Flex>
          )}
        </div>
      )}

      {hasMatrix && (
        <Flex direction="col" gap="density-md">
          <SectionHeading
            title="Technique × Intent"
            subtitle={
              activeLevel === "grouped"
                ? `Rows are technique subcategories, columns intent families. Each cell shows its worst pooled pair, so a cell never reads safer than its most-vulnerable technique×intent. Darker red = more vulnerable. Click a cell to see the pairs it pools.`
                : `Each cell is the ${aggLabel} for that technique (row) × intent (column). Darker red = more vulnerable. Click a cell to drill down.`
            }
          />
          <Text kind="label/regular/sm" className="opacity-60">
            {`${activeView.rows.length} × ${activeView.cols.length} cells`}
          </Text>
          <ErrorBoundary fallbackMessage="Failed to load the technique/intent heatmap.">
            <TechniqueIntentHeatmap
              view={activeView}
              isDark={isDark}
              onSelect={setSelected}
              hover={hovered}
              onHover={setHovered}
            />
          </ErrorBoundary>
        </Flex>
      )}

      <TechniqueIntentDetailPanel detail={selected} onClose={() => setSelected(null)} />
    </Flex>
  );
};

export default TechniqueIntentPanel;
