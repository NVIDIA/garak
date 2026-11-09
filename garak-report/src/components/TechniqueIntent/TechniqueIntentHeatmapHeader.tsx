/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Compact KUI heading, coverage and chart controls. */
import { Button, ButtonGroup, Flex, PageHeader, Text, Tooltip } from "@kui/react";
import { Info, Minus, Plus } from "lucide-react";
import { HEATMAP_KEYBOARD_HELP } from "./TechniqueIntentHeatmapAccessibility";
interface Props {
  techniques: number;
  count: number;
  first: number;
  total: number;
  onZoom: (direction: "in" | "out") => void;
  onReset: () => void;
}
const TechniqueIntentHeatmapZoom = ({
  count,
  total,
  onZoom,
  onReset,
}: Pick<Props, "count" | "total" | "onZoom" | "onReset">) => (
  <Flex align="center" gap="density-sm">
    <ButtonGroup kind="secondary" color="neutral" size="small" aria-label="Heatmap zoom">
      <Tooltip slotContent="Zoom out">
        <Button
          kind="secondary"
          color="neutral"
          size="small"
          aria-label="Zoom out"
          disabled={count === total}
          onClick={() => onZoom("out")}
        >
          <Minus size={16} aria-hidden="true" />
        </Button>
      </Tooltip>
      <Tooltip slotContent="Zoom in">
        <Button
          kind="secondary"
          color="neutral"
          size="small"
          aria-label="Zoom in"
          disabled={count <= 1}
          onClick={() => onZoom("in")}
        >
          <Plus size={16} aria-hidden="true" />
        </Button>
      </Tooltip>
    </ButtonGroup>
    <Button kind="tertiary" size="small" disabled={count === total} onClick={onReset}>
      Reset zoom
    </Button>
  </Flex>
);

const TechniqueIntentHeatmapHeader = ({
  techniques,
  count,
  first,
  total,
  onZoom,
  onReset,
}: Props) => (
  <PageHeader
    kind="flat"
    density="compact"
    attributes={{ PageHeaderFooter: { style: { alignSelf: "start" } } }}
    slotHeading={
      <Flex align="center" gap="density-xs">
        <Text kind="title/sm" role="heading" aria-level={2}>
          Technique × Intent
        </Text>
        <Tooltip
          slotContent={`Select a cell, technique or intent for details below. Zoom in for more detail, then drag the navigation bar across intents. Reset zoom returns to the full matrix. ${HEATMAP_KEYBOARD_HELP}`}
          style={{ maxWidth: 320 }}
        >
          <Button kind="tertiary" size="small" aria-label="About the heatmap">
            <Info size={16} aria-hidden="true" />
          </Button>
        </Tooltip>
      </Flex>
    }
    slotDescription={
      <Text
        kind="body/regular/sm"
        aria-live="polite"
        style={{ color: "var(--text-color-secondary)" }}
      >
        {techniques} techniques ·{" "}
        {count === total ? `${total} intents` : `Intents ${first + 1}–${first + count} of ${total}`}
      </Text>
    }
    slotActions={
      <TechniqueIntentHeatmapZoom count={count} total={total} onZoom={onZoom} onReset={onReset} />
    }
  />
);
export default TechniqueIntentHeatmapHeader;
