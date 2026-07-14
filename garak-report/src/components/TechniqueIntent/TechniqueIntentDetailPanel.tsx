/**
 * @file TechniqueIntentDetailPanel.tsx
 * @description Drill-down side panel for a selected technique/intent item.
 *              Passing items show an honest "no failures" state; failing items
 *              surface the detectors and probes that contributed to the score as
 *              context. (Per-attempt hit evidence lives in the interactive
 *              garak-ui and is intentionally out of scope for the static report.)
 * @module components/TechniqueIntent
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { type CSSProperties } from "react";
import { SidePanel, Flex, Stack, Text, Badge, StatusMessage, Divider } from "@kui/react";
import { ShieldCheck } from "lucide-react";
import { scoreToDefcon, DEFCON_LABELS, RISK_RAMP_COLORS, type DefconLevel } from "../../constants";
import { formatRate } from "../../utils/formatPercentage";
import type { TaxonomyDetail } from "./types";

const PANEL_STYLE = {
  "--side-panel-width": "min(560px, 92vw)",
} as CSSProperties;

/** Props for TechniqueIntentDetailPanel component */
interface TechniqueIntentDetailPanelProps {
  /** The selected item to show, or null when the panel is closed. */
  detail: TaxonomyDetail | null;
  /** Called when the panel requests to close. */
  onClose: () => void;
}

const HEADINGS: Record<TaxonomyDetail["kind"], string> = {
  cell: "Technique × Intent",
  technique: "Technique",
  intent: "Intent",
};

/**
 * Risk chip colored from the same ramp as the heatmap/bars, so a given score
 * shows the same color here as it does in the charts.
 */
const RiskChip = ({ defcon }: { defcon: DefconLevel }) => (
  <span
    style={{
      display: "inline-flex",
      alignItems: "center",
      background: RISK_RAMP_COLORS[defcon],
      color: "#fff",
      padding: "2px 8px",
      borderRadius: "var(--radius-sm, 6px)",
      fontSize: 12,
      fontWeight: 600,
      lineHeight: 1.4,
      whiteSpace: "nowrap",
    }}
  >
    DC-{defcon} · {DEFCON_LABELS[defcon] ?? DEFCON_LABELS.default}
  </span>
);

/** Static, non-actionable chip list (e.g. detectors or probes that contributed). */
const StaticChips = ({ label, items }: { label: string; items: string[] }) => {
  if (!items.length) return null;
  return (
    <Stack gap="density-xs">
      <Text kind="label/bold/sm">
        {label} ({items.length})
      </Text>
      <Flex gap="density-xs" wrap="wrap">
        {items.map(item => (
          <Badge key={item} color="gray" kind="outline">
            <Text kind="label/regular/xs">{item}</Text>
          </Badge>
        ))}
      </Flex>
    </Stack>
  );
};

/**
 * Right-side drawer for a clicked heatmap cell or technique/intent bar.
 *
 * Behaviour by item severity:
 *  - Passing item (score === 1): shows an honest "no failures" state.
 *  - Failing item: lists the detectors that contributed as context, plus the
 *    probes when more than one is involved.
 */
const TechniqueIntentDetailPanel = ({ detail, onClose }: TechniqueIntentDetailPanelProps) => {
  const defcon = detail ? scoreToDefcon(detail.score) : 4;
  const hasFailures = detail ? detail.score < 1 : false;
  const heading = detail ? HEADINGS[detail.kind] : "Details";

  // Show the subtitle only when it carries real info (a cell's intent), not when
  // it just repeats the kind already shown in the panel heading.
  const singleProbe = detail?.probes?.length === 1 ? detail.probes[0] : undefined;
  const renderSummary = () =>
    detail && (
      <Stack gap="density-xs">
        <Text kind="title/md">{detail.title}</Text>
        {detail.kind === "cell" && detail.subtitle && (
          <Text kind="body/regular/sm" className="opacity-70">
            {detail.subtitle}
          </Text>
        )}
        <Flex align="center" gap="density-sm" wrap="wrap" style={{ marginTop: "var(--density-xs)" }}>
          <Text kind="title/lg">{formatRate(detail.score)}</Text>
          <RiskChip defcon={defcon} />
          <Text kind="body/regular/sm" className="opacity-60">
            over {detail.nEvaluations.toLocaleString()} evaluation
            {detail.nEvaluations === 1 ? "" : "s"}
          </Text>
        </Flex>
        {singleProbe && (
          <Text kind="body/regular/sm" className="opacity-60">
            Probe:{" "}
            <span style={{ fontFamily: "var(--font-family-mono, monospace)" }}>{singleProbe}</span>
          </Text>
        )}
      </Stack>
    );

  return (
    <SidePanel
      side="right"
      style={PANEL_STYLE}
      open={!!detail}
      onOpenChange={open => {
        if (!open) onClose();
      }}
      slotHeading={heading}
    >
      {detail && (
        <Stack gap="density-lg">
          {renderSummary()}
          <Divider />

          {/* Passing item: nothing flagged. Be explicit and positive. */}
          {!hasFailures && (
            <StatusMessage
              size="small"
              slotIcon={<ShieldCheck size={20} />}
              slotHeading="No failures recorded"
              slotSubheading={`The target passed every evaluation for this ${detail.kind === "cell" ? "combination" : detail.kind}. There are no attempts to inspect.`}
            />
          )}

          {/* Failing item: list the detectors that contributed as context. */}
          {hasFailures && <StaticChips label="Detectors" items={detail.detectors} />}

          {/* A single probe is shown inline in the header; only list here when several. */}
          {detail.probes && detail.probes.length > 1 && (
            <>
              <Divider />
              <StaticChips label="Probes" items={detail.probes} />
            </>
          )}
        </Stack>
      )}
    </SidePanel>
  );
};

export default TechniqueIntentDetailPanel;
