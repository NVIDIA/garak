/**
 * @file TechniqueIntentPanel.tsx
 * @description Orchestrates the technique/intent taxonomy view. Leads with a
 *              compact executive summary, surfaces genuine technique×intent
 *              interactions only when they exist ("Notable pairings"), and drills
 *              into tabbed "By technique" / "By intent" accordion lists that
 *              expand inline (Modules-tab style). No heatmap: for the common
 *              separable matrix it just re-encodes the two lists as a grid.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useCallback, useMemo, useState, type ReactNode } from "react";
import {
  Card,
  Flex,
  Notification,
  SegmentedControl,
  Stack,
  StatusMessage,
  Tabs,
  Text,
} from "@kui/react";
import type { TaxonomyScoreMap, TechniqueIntentMatrix } from "../../types/ReportEntry";
import { DEFCON_LABELS, DEFCON_LEVELS, scoreToDefcon } from "../../constants";
import { formatRate } from "../../utils/formatPercentage";
import {
  buildMatrixView,
  findNotablePairings,
  type MatrixLevel,
  type NotablePairing,
} from "../../utils/techniqueIntentRollup";
import type { SortOption } from "../../hooks/useModuleFilters";
import useSeverityColor from "../../hooks/useSeverityColor";
import DefconBadge from "../DefconBadge";
import ErrorBoundary from "../ErrorBoundary";
import ReportFilterBar from "../ReportFilterBar";
import TaxonomyAxisList, { FlatTaxonomyList } from "./TaxonomyAxisList";

/** Props for TechniqueIntentPanel component */
export interface TechniqueIntentPanelProps {
  /** Flat intent -> score map (`digest.intent`) */
  intent?: TaxonomyScoreMap;
  /** Flat technique -> score map (`digest.technique`) */
  technique?: TaxonomyScoreMap;
  /** Nested technique -> intent -> score matrix (`digest.technique_intent`) */
  techniqueIntent?: TechniqueIntentMatrix;
  /** Theme mode for styling (unused now the charts are gone; kept for the API) */
  isDark?: boolean;
}

type AxisTab = "technique" | "intent";

const hasEntries = (obj?: Record<string, unknown>): boolean =>
  !!obj && Object.keys(obj).length > 0;

const LEVEL_ITEMS = [
  { value: "leaf", children: "All leaves" },
  { value: "grouped", children: "Grouped" },
];

/** Switches the lists between grouped (worst-case roll-up) and full-leaf levels. */
const LevelToggle = ({
  level,
  onChange,
}: {
  level: MatrixLevel;
  onChange: (level: MatrixLevel) => void;
}) => (
  <Flex gap="density-sm" align="center" style={{ flexShrink: 0 }}>
    <Text kind="label/bold/md">Detail level:</Text>
    <SegmentedControl
      size="small"
      value={level}
      onValueChange={value => onChange(value as MatrixLevel)}
      items={LEVEL_ITEMS}
    />
  </Flex>
);

/**
 * Severity summary for the tab: a single stacked bar showing how the concrete
 * technique×intent pairings partition across the five DEFCON levels, each in its
 * own colour, over a legend that names every band and its count. The bar carries
 * the proportions, so the legend stays count-only (no redundant per-band share).
 */
const SeveritySummary = ({
  counts,
  total,
  techniques,
  intents,
}: {
  counts: Record<number, number>;
  total: number;
  techniques: number;
  intents: number;
}) => {
  const { getDefconColor } = useSeverityColor();
  const present = DEFCON_LEVELS.filter(level => counts[level] > 0);
  return (
    <Card slotHeader={<Text kind="label/bold/md">Pairing severity</Text>}>
      <Stack gap="density-lg">
        <div
          style={{
            display: "flex",
            width: "100%",
            height: 14,
            borderRadius: 4,
            overflow: "hidden",
          }}
        >
          {DEFCON_LEVELS.map(level => {
            const width = total > 0 ? (counts[level] / total) * 100 : 0;
            return width > 0 ? (
              <div
                key={level}
                style={{ width: `${width}%`, backgroundColor: getDefconColor(level) }}
                title={`${DEFCON_LABELS[level]}: ${counts[level].toLocaleString()}`}
              />
            ) : null;
          })}
        </div>
        <Flex gap="density-2xl" wrap="wrap" align="center">
          {present.map(level => (
            <Flex key={level} align="center" gap="density-sm">
              <DefconBadge defcon={level} showLabel />
              <Text kind="label/bold/md">{counts[level].toLocaleString()}</Text>
            </Flex>
          ))}
        </Flex>
        <Text kind="label/regular/sm" className="opacity-60">
          {total.toLocaleString()} pairings · {techniques.toLocaleString()} techniques ·{" "}
          {intents.toLocaleString()} intents
        </Text>
      </Stack>
    </Card>
  );
};

/**
 * Warning callout for genuine interactions — pairings that fail far worse than
 * their technique or intent does elsewhere. Renders only when such pairings
 * exist (it's silent for the common separable matrix).
 */
const NotablePairings = ({ items }: { items: NotablePairing[] }) => (
  <Notification
    status="warning"
    density="spacious"
    slotHeading="Notable pairings"
    slotSubheading={
      <Stack gap="density-md">
        <Text kind="body/regular/sm">
          These combinations fail far worse than the technique or the intent does on its own — the
          kind of interaction worth a closer look.
        </Text>
        <Stack gap="density-sm">
          {items.map(p => (
            <Flex
              key={`${p.rowKey}\u0000${p.colKey}`}
              justify="between"
              align="center"
              gap="density-md"
              wrap="wrap"
            >
              <Flex align="center" gap="density-sm">
                <DefconBadge defcon={scoreToDefcon(p.score)} />
                <Text kind="label/bold/sm">{formatRate(p.score)}</Text>
                <Text kind="body/regular/sm">
                  {p.rowLabel} × {p.colLabel}
                </Text>
              </Flex>
              <Text kind="label/regular/xs" className="opacity-60">
                technique reaches {formatRate(p.rowBest, 0)} elsewhere · intent reaches{" "}
                {formatRate(p.colBest, 0)} elsewhere
              </Text>
            </Flex>
          ))}
        </Stack>
      </Stack>
    }
  />
);

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
  const [level, setLevel] = useState<MatrixLevel>("leaf");
  const [selectedDefcons, setSelectedDefcons] = useState<number[]>([...DEFCON_LEVELS]);
  const [sortBy, setSortBy] = useState<SortOption>("defcon");
  const [activeTab, setActiveTab] = useState<AxisTab>("technique");
  const [techOpen, setTechOpen] = useState<string>("");
  const [intentOpen, setIntentOpen] = useState<string>("");

  const viewGrouped = useMemo(
    () => buildMatrixView(techniqueIntent ?? {}, "grouped"),
    [techniqueIntent],
  );
  const viewLeaf = useMemo(() => buildMatrixView(techniqueIntent ?? {}, "leaf"), [techniqueIntent]);
  const reducible = viewGrouped.reducible;
  const activeLevel: MatrixLevel = reducible ? level : "leaf";
  const activeView = activeLevel === "grouped" ? viewGrouped : viewLeaf;

  const hasMatrix = hasEntries(techniqueIntent);
  const hasTechnique = hasEntries(technique);
  const hasIntent = hasEntries(intent);

  // Summary + interaction signal are derived from the concrete leaf pairings so
  // they stay stable regardless of the Grouped/Leaf toggle below.
  const notable = useMemo(() => findNotablePairings(viewLeaf), [viewLeaf]);
  const stats = useMemo(() => {
    const counts: Record<number, number> = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    let total = 0;
    for (const row of viewLeaf.rows) {
      for (const col of viewLeaf.cols) {
        const cell = viewLeaf.cell(row, col);
        if (!cell) continue;
        counts[scoreToDefcon(cell.score)] += 1;
        total += 1;
      }
    }
    return {
      counts,
      total, // sum of populated cells, so the bar's bands fill the whole width
      techniques: viewLeaf.rows.length,
      intents: viewLeaf.cols.length,
    };
  }, [viewLeaf]);

  const toggleDefcon = useCallback((defcon: number) => {
    setSelectedDefcons(prev =>
      prev.includes(defcon) ? prev.filter(d => d !== defcon) : [...prev, defcon],
    );
  }, []);

  // Switching level remaps every key (grouped vs leaf), so clear stale open rows.
  const changeLevel = useCallback((next: MatrixLevel) => {
    setLevel(next);
    setTechOpen("");
    setIntentOpen("");
  }, []);

  if (!hasMatrix && !hasTechnique && !hasIntent) {
    return (
      <StatusMessage
        size="medium"
        slotHeading="No technique/intent data in this report"
        slotSubheading="This report was generated without technique and intent taxonomy tags."
      />
    );
  }

  const tabItems = hasMatrix
    ? [
        {
          value: "technique",
          children: "By technique",
          slotContent: (
            // KUI tab panels align children to flex-start, so the list must
            // claim full width explicitly (the same trick the Modules tab uses).
            <Flex direction="col" style={{ width: "100%" }}>
              <ErrorBoundary fallbackMessage="Failed to load the technique list.">
                <TaxonomyAxisList
                  view={activeView}
                  axis="technique"
                  selectedDefcons={selectedDefcons}
                  sortBy={sortBy}
                  openValue={techOpen}
                  onOpenChange={setTechOpen}
                  isDark={isDark}
                />
              </ErrorBoundary>
            </Flex>
          ),
        },
        {
          value: "intent",
          children: "By intent",
          slotContent: (
            <Flex direction="col" style={{ width: "100%" }}>
              <ErrorBoundary fallbackMessage="Failed to load the intent list.">
                <TaxonomyAxisList
                  view={activeView}
                  axis="intent"
                  selectedDefcons={selectedDefcons}
                  sortBy={sortBy}
                  openValue={intentOpen}
                  onOpenChange={setIntentOpen}
                  isDark={isDark}
                />
              </ErrorBoundary>
            </Flex>
          ),
        },
      ]
    : [
        hasTechnique && {
          value: "technique",
          children: "By technique",
          slotContent: (
            <Flex direction="col" style={{ width: "100%" }}>
              <ErrorBoundary fallbackMessage="Failed to load the technique list.">
                <FlatTaxonomyList
                  data={technique!}
                  axis="technique"
                  selectedDefcons={selectedDefcons}
                  sortBy={sortBy}
                  openValue={techOpen}
                  onOpenChange={setTechOpen}
                />
              </ErrorBoundary>
            </Flex>
          ),
        },
        hasIntent && {
          value: "intent",
          children: "By intent",
          slotContent: (
            <Flex direction="col" style={{ width: "100%" }}>
              <ErrorBoundary fallbackMessage="Failed to load the intent list.">
                <FlatTaxonomyList
                  data={intent!}
                  axis="intent"
                  selectedDefcons={selectedDefcons}
                  sortBy={sortBy}
                  openValue={intentOpen}
                  onOpenChange={setIntentOpen}
                />
              </ErrorBoundary>
            </Flex>
          ),
        },
      ].filter(Boolean);

  // Keep the active tab valid for marginal-only reports that may lack one axis.
  const tabValue = tabItems.some(t => t && t.value === activeTab)
    ? activeTab
    : (tabItems[0] && tabItems[0].value) || "technique";

  return (
    <Flex direction="col" gap="density-2xl" style={{ width: "100%" }}>
      {hasMatrix && (
        <SeveritySummary
          counts={stats.counts}
          total={stats.total}
          techniques={stats.techniques}
          intents={stats.intents}
        />
      )}

      {notable.length > 0 && <NotablePairings items={notable} />}

      <Flex direction="col" gap="density-sm">
        <ReportFilterBar
          selectedDefcons={selectedDefcons}
          onToggleDefcon={toggleDefcon}
          sortBy={sortBy}
          onSortChange={setSortBy}
          slotEnd={reducible ? <LevelToggle level={activeLevel} onChange={changeLevel} /> : undefined}
        />
        <Tabs
          value={tabValue}
          onValueChange={value => setActiveTab(value as AxisTab)}
          items={
            tabItems.filter(Boolean) as {
              value: string;
              children: string;
              slotContent: ReactNode;
            }[]
          }
        />
      </Flex>
    </Flex>
  );
};

export default TechniqueIntentPanel;
