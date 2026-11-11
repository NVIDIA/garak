/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Persistent selected result, sharing the existing pairing detail presentation. */
import { useEffect, useRef } from "react";
import { Button, Flex, Stack, Text } from "@kui/react";
import type { MatrixView } from "../../utils/techniqueIntentRollup";
import type { HeatmapSelection } from "../../types/TechniqueIntentHeatmap";
import type { HeatmapGroups } from "../../hooks/useTechniqueIntentHeatmapData";
import CellDetail from "./TechniqueIntentCellDetail";
import GroupDetail from "./TechniqueIntentGroupDetail";
interface Props {
  view: MatrixView;
  groups: HeatmapGroups;
  selection: HeatmapSelection;
  isDark?: boolean;
  onClear: () => void;
  onProbeSelect?: (probe: string) => void;
}
const TechniqueIntentHeatmapDetail = ({
  view,
  groups,
  selection,
  isDark,
  onClear,
  onProbeSelect,
}: Props) => {
  const ref = useRef<HTMLDivElement>(null);
  const cell =
    selection.axis === "cell" ? view.cell(selection.technique, selection.intent) : undefined;
  const group = selection.axis !== "cell" ? groups[selection.axis].get(selection.key) : undefined;
  useEffect(() => {
    ref.current?.scrollIntoView?.({
      behavior: window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches
        ? "auto"
        : "smooth",
      block: "start",
    });
  }, [selection]);
  if (!cell && !group) return null;
  const title =
    selection.axis === "cell"
      ? `${view.rowLabel(selection.technique)} × ${view.colLabel(selection.intent)}`
      : group?.label;
  return (
    <Stack ref={ref} gap="density-md" style={{ scrollMarginTop: "4rem" }}>
      <Flex align="center" justify="between" gap="density-md" wrap="wrap">
        <Text kind="title/sm">{title}</Text>
        <Button kind="tertiary" size="small" onClick={onClear}>
          Clear selection
        </Button>
      </Flex>
      {selection.axis === "cell" && (
        <>
          {view.rowDescription(selection.technique) && (
            <Text kind="body/regular/sm">{view.rowDescription(selection.technique)}</Text>
          )}
          {view.colDescription(selection.intent) && (
            <Text kind="body/regular/sm">{view.colDescription(selection.intent)}</Text>
          )}
        </>
      )}
      {cell && <CellDetail cell={cell} onProbeSelect={onProbeSelect} />}
      {group && (
        <>
          {group.description && <Text kind="body/regular/sm">{group.description}</Text>}
          <GroupDetail
            key={`${selection.axis}:${group.key}`}
            group={group}
            childNoun={selection.axis === "technique" ? "intent" : "technique"}
            isDark={isDark}
            onProbeSelect={onProbeSelect}
          />
        </>
      )}
    </Stack>
  );
};
export default TechniqueIntentHeatmapDetail;
