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
import { Flex, Grid, Notification, Stack, StatusMessage, Tabs, Text } from "@kui/react";
import type { IntentTypology, TechniqueIntentMatrix } from "../../types/ReportEntry";
import { DEFCON_LEVELS, scoreToDefcon } from "../../constants";
import { formatRate } from "../../utils/formatPercentage";
import {
  buildMatrixView,
  findNotablePairings,
  type NotablePairing,
} from "../../utils/techniqueIntentRollup";
import type { SortOption } from "../../hooks/useModuleFilters";
import DefconBadge from "../DefconBadge";
import ErrorBoundary from "../ErrorBoundary";
import ReportFilterBar from "../ReportFilterBar";
import TaxonomyAxisList from "./TaxonomyAxisList";

/** Props for TechniqueIntentPanel component */
export interface TechniqueIntentPanelProps {
  /** Pooled technique×intent matrix (`digest.technique_intent_matrix`) */
  techniqueIntent?: TechniqueIntentMatrix;
  /** Intent labels/descriptions (`digest.intent_typology`) for column naming */
  intentTypology?: IntentTypology;
  /** Theme mode for styling (unused now the charts are gone; kept for the API) */
  isDark?: boolean;
}

type AxisTab = "technique" | "intent";

const hasEntries = (obj?: Record<string, unknown>): boolean => !!obj && Object.keys(obj).length > 0;

/**
 * Warning callout for genuine interactions — pairings that fail far worse than
 * their technique or intent does elsewhere. Renders only when such pairings
 * exist (it's silent for the common separable matrix). Each row is a shortcut
 * that opens the pairing in the technique list below.
 */
const NotablePairings = ({
  items,
  onSelect,
}: {
  items: NotablePairing[];
  onSelect: (pairing: NotablePairing) => void;
}) => (
  <Notification
    status="warning"
    density="spacious"
    slotHeading="Notable pairings"
    slotSubheading={
      <Stack gap="density-lg">
        <Text kind="body/regular/sm" className="opacity-70">
          These combinations fail far worse than the technique or the intent does on its own — the
          kind of interaction worth a closer look. Select one to open it in the list below.
        </Text>
        <Grid cols={{ base: 1, lg: 2 }} gap="density-md">
          {items.map(p => (
            <button
              key={`${p.rowKey}\u0000${p.colKey}`}
              type="button"
              onClick={() => onSelect(p)}
              className="w-full cursor-pointer rounded text-left transition-opacity hover:opacity-70"
              style={{ background: "none", border: 0, padding: 0 }}
            >
              <Flex align="center" gap="density-sm">
                <DefconBadge defcon={scoreToDefcon(p.score)} />
                <Text kind="label/bold/md">{formatRate(p.score)}</Text>
                <Text kind="body/regular/md">
                  {p.rowLabel} × {p.colLabel}
                </Text>
              </Flex>
            </button>
          ))}
        </Grid>
      </Stack>
    }
  />
);

/**
 * Renders the technique/intent taxonomy view. Shows a graceful empty state when
 * the report carries no technique×intent matrix (e.g. older reports).
 */
const TechniqueIntentPanel = ({
  techniqueIntent,
  intentTypology,
  isDark,
}: TechniqueIntentPanelProps) => {
  const [selectedDefcons, setSelectedDefcons] = useState<number[]>([...DEFCON_LEVELS]);
  const [sortBy, setSortBy] = useState<SortOption>("defcon");
  const [activeTab, setActiveTab] = useState<AxisTab>("technique");
  const [techOpen, setTechOpen] = useState<string>("");
  const [intentOpen, setIntentOpen] = useState<string>("");
  // Intent to auto-open inside the currently-open technique (set when a notable
  // pairing is clicked; cleared on any manual accordion interaction).
  const [focusIntent, setFocusIntent] = useState<string>("");
  // Bumped on every notable-pairing click so re-clicking the same one re-scrolls.
  const [focusNonce, setFocusNonce] = useState(0);

  const view = useMemo(
    () => buildMatrixView(techniqueIntent ?? {}, intentTypology),
    [techniqueIntent, intentTypology]
  );

  const hasMatrix = hasEntries(techniqueIntent);

  const notable = useMemo(() => findNotablePairings(view), [view]);

  const toggleDefcon = useCallback((defcon: number) => {
    setSelectedDefcons(prev =>
      prev.includes(defcon) ? prev.filter(d => d !== defcon) : [...prev, defcon]
    );
  }, []);

  // Manual open/close on the technique list drops any pending notable-pairing focus.
  const handleTechOpen = useCallback((next: string) => {
    setTechOpen(next);
    setFocusIntent("");
  }, []);

  // Jump from a notable pairing to its detail: open the technique tab and
  // pre-select the intent. The detail reveals itself once the accordion opens.
  const handleNotableSelect = useCallback((pairing: NotablePairing) => {
    setActiveTab("technique");
    setTechOpen(pairing.rowKey);
    setFocusIntent(pairing.colKey);
    setFocusNonce(n => n + 1);
  }, []);

  if (!hasMatrix) {
    return (
      <StatusMessage
        size="medium"
        slotHeading="No technique/intent data in this report"
        slotSubheading="This report was generated without technique and intent taxonomy tags."
      />
    );
  }

  const tabItems = [
    {
      value: "technique",
      children: "By technique",
      slotContent: (
        // KUI tab panels align children to flex-start, so the list must
        // claim full width explicitly (the same trick the Modules tab uses).
        <Flex direction="col" style={{ width: "100%" }}>
          <ErrorBoundary fallbackMessage="Failed to load the technique list.">
            <TaxonomyAxisList
              view={view}
              axis="technique"
              selectedDefcons={selectedDefcons}
              sortBy={sortBy}
              openValue={techOpen}
              onOpenChange={handleTechOpen}
              focusSecondaryKey={focusIntent}
              focusNonce={focusNonce}
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
              view={view}
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
  ];

  return (
    <Flex direction="col" gap="density-2xl" style={{ width: "100%" }}>
      {notable.length > 0 && <NotablePairings items={notable} onSelect={handleNotableSelect} />}

      <Flex direction="col" gap="density-sm">
        <ReportFilterBar
          selectedDefcons={selectedDefcons}
          onToggleDefcon={toggleDefcon}
          sortBy={sortBy}
          onSortChange={setSortBy}
        />
        <Tabs
          value={activeTab}
          onValueChange={value => setActiveTab(value as AxisTab)}
          items={tabItems as { value: string; children: string; slotContent: ReactNode }[]}
        />
      </Flex>
    </Flex>
  );
};

export default TechniqueIntentPanel;
