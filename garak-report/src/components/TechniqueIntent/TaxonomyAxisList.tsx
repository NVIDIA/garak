/**
 * @file TaxonomyAxisList.tsx
 * @description Modules-style accordion list for one taxonomy axis. Each primary
 *              entry (a technique, or an intent) expands to its worst-first
 *              cross-axis pairings, and each pairing expands again to an inline
 *              detail block — the pooled technique×intent pairs, concrete
 *              pass/fail counts, and honest "no failures" state that used to
 *              live in a side drawer.
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Fragment, useMemo, useState } from "react";
import {
  Accordion,
  Badge,
  Divider,
  Flex,
  Grid,
  Panel,
  Stack,
  StatusMessage,
  Text,
} from "@kui/react";
import { ShieldCheck } from "lucide-react";
import { scoreToDefcon } from "../../constants";
import { formatRate } from "../../utils/formatPercentage";
import { shortenTechnique } from "../../utils/taxonomyLabels";
import useSeverityColor from "../../hooks/useSeverityColor";
import DefconBadge from "../DefconBadge";
import TaxonomyCellChart from "./TaxonomyCellChart";
import {
  buildAxisGroups,
  type AxisGroup,
  type MatrixCell,
  type MatrixView,
  type TaxonomyAxis,
} from "../../utils/techniqueIntentRollup";
import type { SortOption } from "../../hooks/useModuleFilters";

/** With fewer cells than this there's nothing to compare; show the detail directly. */
const MIN_CELLS_FOR_CHART = 2;

/** Props for TaxonomyAxisList component */
interface TaxonomyAxisListProps {
  /** Active-level matrix view. */
  view: MatrixView;
  /** Which axis is primary (the other nests inside each entry). */
  axis: TaxonomyAxis;
  /** DEFCON levels to keep (group is shown when its worst score's level is in). */
  selectedDefcons: number[];
  /** Sort order for the primary entries. */
  sortBy: SortOption;
  /** Controlled open primary key (so navigation can drive it). */
  openValue: string;
  /** Notifies the parent when the open primary entry changes. */
  onOpenChange: (value: string) => void;
  /** Theme mode, forwarded to the inner pairing chart. */
  isDark?: boolean;
}

/** Singular noun for the nested axis, used in per-group meta lines. */
const CHILD_NOUN: Record<TaxonomyAxis, string> = {
  technique: "intent",
  intent: "technique",
};

const pluralize = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

/**
 * Stacked score + DEFCON badge pair, matching the Modules accordion triggers:
 * the pass-rate badge sits directly above the DEFCON badge, both fixed-width.
 */
const ScoreBadges = ({ score, defcon }: { score: number; defcon: number }) => {
  const { getDefconBadgeColor } = useSeverityColor();
  const color = getDefconBadgeColor(defcon);
  return (
    <Flex direction="col" gap="density-sm" style={{ flexShrink: 0 }}>
      <Badge color={color} kind="solid" className="w-[70px]">
        <Text kind="label/bold/xl">{formatRate(score, 0)}</Text>
      </Badge>
      <Badge color={color} kind="outline" className="w-[70px]">
        <Text kind="label/bold/md">DC-{defcon}</Text>
      </Badge>
    </Flex>
  );
};

/**
 * Worst-first list of the technique×intent pairs a grouped cell pools. Makes the
 * conservative roll-up transparent: you can see exactly which pair drives the
 * worst-case cell score and how many pairs sit behind it.
 */
const PooledLeaves = ({ leaves }: { leaves: MatrixCell["leaves"] }) => (
  <Stack gap="density-xs">
    <Text kind="label/bold/md">Pooled pairs ({leaves.length})</Text>
    <Stack gap="density-xs">
      {leaves.map((leaf, index) => (
        <Fragment key={`${leaf.technique}\u0000${leaf.intent}`}>
          {index > 0 && <Divider />}
          <Flex align="center" justify="space-between" gap="density-sm">
            <Text kind="body/regular/md">
              {leaf.techniqueName ?? shortenTechnique(leaf.technique)} ×{" "}
              {leaf.intentName ?? leaf.intent}
            </Text>
            <Flex align="center" gap="density-xs">
              <DefconBadge defcon={scoreToDefcon(leaf.score)} />
              <Text kind="label/bold/md">{formatRate(leaf.score)}</Text>
              <Text kind="label/regular/sm" className="opacity-50">
                ({leaf.nEvaluations.toLocaleString()})
              </Text>
            </Flex>
          </Flex>
        </Fragment>
      ))}
    </Stack>
  </Stack>
);

/** Single labelled figure used in the detail header's stat row. */
const Stat = ({ label, value }: { label: string; value: string }) => (
  <Stack gap="density-xxs">
    <Text kind="label/regular/sm" className="opacity-60">
      {label}
    </Text>
    <Text kind="label/bold/lg">{value}</Text>
  </Stack>
);

/**
 * Inline detail for one cross-axis pairing — the former drawer body. Leads with
 * a severity header and the concrete pass/fail counts the digest carries (the
 * abstract percentage made tangible), then the pooled pairs behind a rolled-up
 * cell. The digest pools detectors into a count here, so we report how many
 * judges scored the pairing rather than inventing a per-detector breakdown.
 */
const CellDetail = ({ cell, title }: { cell: MatrixCell; title?: string }) => {
  const { getSeverityLabelByLevel, getDefconBadgeColor } = useSeverityColor();
  const defcon = scoreToDefcon(cell.score);
  const hasFailures = cell.score < 1;
  const failed = Math.max(cell.nEvaluations - cell.passed - cell.nones, 0);
  return (
    <Panel>
      <Stack gap="density-lg">
        <Stack gap="density-sm">
          <Flex gap="density-md" align="center" wrap="wrap">
            <DefconBadge defcon={defcon} />
            {title && <Text kind="title/sm">{title}</Text>}
            <Badge color={getDefconBadgeColor(defcon)} kind="outline">
              <Text kind="label/bold/sm">{getSeverityLabelByLevel(defcon)}</Text>
            </Badge>
          </Flex>
          <Flex gap="density-2xl" wrap="wrap">
            <Stat
              label={cell.leafCount > 1 ? "Pass rate (worst case)" : "Pass rate"}
              value={formatRate(cell.score)}
            />
            <Stat
              label="Passed"
              value={`${cell.passed.toLocaleString()} of ${cell.nEvaluations.toLocaleString()}`}
            />
            <Stat label="Failed" value={failed.toLocaleString()} />
            {cell.nones > 0 && (
              <Stat label="Undetermined" value={cell.nones.toLocaleString()} />
            )}
            {cell.leafCount > 1 && (
              <Stat label="Pooled pairs" value={cell.leafCount.toLocaleString()} />
            )}
          </Flex>
          <Text kind="label/regular/xs" className="opacity-60">
            Counts are evaluations — one per attempt scored by each of{" "}
            {pluralize(cell.nDetectors, "detector")}.
          </Text>
        </Stack>

        {cell.leafCount > 1 && (
          <>
            <Divider />
            <PooledLeaves leaves={cell.leaves} />
          </>
        )}

        <Divider />
        {!hasFailures ? (
          <StatusMessage
            size="small"
            slotIcon={<ShieldCheck size={20} />}
            slotHeading="No failures recorded"
            slotSubheading="The target passed every evaluation for this pairing. There are no attempts to inspect."
          />
        ) : (
          <Text kind="body/regular/sm" className="opacity-60">
            A response counts as a failure when any detector flags it.
          </Text>
        )}
      </Stack>
    </Panel>
  );
};

/**
 * Degenerate fallback for a group with a single pairing: there's nothing to
 * compare or select, so skip the chart and show the detail straight away.
 */
const GroupSingleChild = ({ group }: { group: AxisGroup }) => {
  const only = group.cells[0];
  return (
    <Stack paddingY="density-sm">
      <CellDetail cell={only.cell} title={only.otherLabel} />
    </Stack>
  );
};

/** Bar chart of a group's pairings with click-to-detail — default for larger groups. */
const GroupChildrenChart = ({
  group,
  childNoun,
  isDark,
}: {
  group: AxisGroup;
  childNoun: string;
  isDark?: boolean;
}) => {
  const [selected, setSelected] = useState<string | null>(null);
  const selectedEntry = group.cells.find(c => c.otherKey === selected);
  return (
    <Stack gap="density-md" paddingY="density-sm">
      <Text kind="label/regular/sm" className="opacity-60">
        Pass rate by {childNoun}. Click a bar for the pass/fail breakdown.
      </Text>
      <Grid cols={selectedEntry ? 2 : 1} gap="density-lg" className="items-start">
        <TaxonomyCellChart
          cells={group.cells}
          isDark={isDark}
          selectedKey={selected}
          onSelect={setSelected}
        />
        {selectedEntry && (
          <CellDetail cell={selectedEntry.cell} title={selectedEntry.otherLabel} />
        )}
      </Grid>
    </Stack>
  );
};

/**
 * Inner content for an open primary entry: a worst-first bar chart of its
 * pairings with click-to-detail in a side panel (the same model both axes use),
 * collapsing to a bare detail block when there's only a single pairing.
 */
const GroupChildren = ({
  group,
  childNoun,
  isDark,
}: {
  group: AxisGroup;
  childNoun: string;
  isDark?: boolean;
}) =>
  group.cells.length >= MIN_CELLS_FOR_CHART ? (
    <GroupChildrenChart group={group} childNoun={childNoun} isDark={isDark} />
  ) : (
    <GroupSingleChild group={group} />
  );

/**
 * Renders the worst-first accordion list for one axis. Filtering and sorting are
 * applied to the primary entries; the order otherwise follows the matrix view's
 * own worst-first ranking.
 */
const TaxonomyAxisList = ({
  view,
  axis,
  selectedDefcons,
  sortBy,
  openValue,
  onOpenChange,
  isDark,
}: TaxonomyAxisListProps) => {
  const groups = useMemo(() => buildAxisGroups(view, axis), [view, axis]);
  const childNoun = CHILD_NOUN[axis];

  const visible = useMemo(() => {
    const filtered = groups.filter(g => selectedDefcons.includes(scoreToDefcon(g.score)));
    if (sortBy === "alphabetical") {
      return [...filtered].sort((a, b) => a.label.localeCompare(b.label));
    }
    return filtered; // worst-first is the view's native order
  }, [groups, selectedDefcons, sortBy]);

  if (!visible.length) {
    return (
      <StatusMessage
        size="small"
        slotHeading={`No ${axis}s match the current filters`}
        slotSubheading="Try enabling more DEFCON levels above."
      />
    );
  }

  return (
    <Accordion
      value={openValue}
      onValueChange={value => onOpenChange(value as string)}
      items={visible.map(group => {
        const defcon = scoreToDefcon(group.score);
        return {
          value: group.key,
          slotTrigger: (
            <Flex gap="density-lg" align="center" style={{ width: "100%" }}>
              <ScoreBadges score={group.score} defcon={defcon} />
              <Stack gap="density-xs" align="start">
                <Text kind="label/bold/2xl">{group.label}</Text>
                {group.description && (
                  <Text kind="body/regular/sm" className="opacity-70">
                    {group.description}
                  </Text>
                )}
                <Text kind="label/regular/sm" className="opacity-60">
                  worst of {pluralize(group.cells.length, childNoun)} ·{" "}
                  {group.nEvaluations.toLocaleString()} evaluations
                </Text>
              </Stack>
            </Flex>
          ),
          slotContent: <GroupChildren group={group} childNoun={childNoun} isDark={isDark} />,
        };
      })}
    />
  );
};

export default TaxonomyAxisList;
