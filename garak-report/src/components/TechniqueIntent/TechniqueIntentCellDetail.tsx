/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Badge, Divider, Flex, Panel, Stack, StatusMessage, Text } from "@kui/react";
import { ShieldCheck } from "lucide-react";
import { scoreToDefcon } from "../../constants";
import { formatRate } from "../../utils/formatPercentage";
import useSeverityColor from "../../hooks/useSeverityColor";
import DefconBadge from "../DefconBadge";
import TechniqueIntentProvenance from "./TechniqueIntentProvenance";
import type { MatrixCell } from "../../utils/techniqueIntentRollup";
const pluralize = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

/** Single labelled figure used in the detail header's stat row. */
const Stat = ({ label, value }: { label: string; value: string }) => (
  <Stack gap="density-xxs">
    <Text kind="label/regular/md" className="opacity-60">
      {label}
    </Text>
    <Text kind="label/bold/xl">{value}</Text>
  </Stack>
);

/**
 * Inline detail for one cross-axis pairing — the former drawer body. Leads with
 * a severity header and the concrete pass/fail counts the digest carries. The
 * digest supplies contributing probe/detector pairs on newer reports.
 */
const CellDetail = ({
  cell,
  title,
  onProbeSelect,
}: {
  cell: MatrixCell;
  title?: string;
  onProbeSelect?: (probe: string) => void;
}) => {
  const { getSeverityLabelByLevel, getDefconBadgeColor } = useSeverityColor();
  const defcon = scoreToDefcon(cell.score);
  const hasFailures = cell.score < 1;
  const failed = Math.max(cell.nEvaluations - cell.passed, 0);
  const hasPrompts = cell.nAttempts > 0; // older reports omit prompt counts
  return (
    <Panel>
      <Stack gap="density-2xl" paddingY="density-sm">
        <Stack gap="density-lg">
          <Flex gap="density-md" align="center" wrap="wrap">
            <DefconBadge defcon={defcon} />
            {title && <Text kind="title/sm">{title}</Text>}
            <Badge color={getDefconBadgeColor(defcon)} kind="outline">
              <Text kind="label/bold/md">{getSeverityLabelByLevel(defcon)}</Text>
            </Badge>
          </Flex>
          <Flex gap="density-2xl" wrap="wrap">
            <Stat label="Pass rate" value={formatRate(cell.score)} />
            <Stat
              label="Passed"
              value={`${cell.passed.toLocaleString()} of ${cell.nEvaluations.toLocaleString()}`}
            />
            <Stat label="Failed" value={failed.toLocaleString()} />
            {cell.nones > 0 && <Stat label="Undetermined" value={cell.nones.toLocaleString()} />}
            {hasPrompts && <Stat label="Prompts" value={cell.nAttempts.toLocaleString()} />}
          </Flex>
          <Text kind="label/regular/sm" className="opacity-60">
            {hasPrompts
              ? `${pluralize(cell.nAttempts, "prompt")} · ${pluralize(
                  cell.nDetectors,
                  "detector"
                )} · ${cell.nEvaluations.toLocaleString()} evaluations.`
              : `Counts are detector evaluations, pooled across ${pluralize(
                  cell.nDetectors,
                  "detector"
                )}.`}
          </Text>
        </Stack>

        {cell.probeDetectorPairs && cell.probeDetectorPairs.length > 0 && (
          <TechniqueIntentProvenance
            pairs={cell.probeDetectorPairs}
            onProbeSelect={onProbeSelect}
          />
        )}
        <Divider />
        {!hasFailures ? (
          <StatusMessage
            size="small"
            slotMedia={<ShieldCheck size={20} />}
            slotHeading="No failures recorded"
            slotSubheading="The target passed every evaluation for this pairing."
          />
        ) : (
          <Text kind="body/regular/md" className="opacity-60">
            A failed evaluation means a detector flagged an output. Undetermined results are
            excluded from the pass rate.
          </Text>
        )}
      </Stack>
    </Panel>
  );
};

export default CellDetail;
