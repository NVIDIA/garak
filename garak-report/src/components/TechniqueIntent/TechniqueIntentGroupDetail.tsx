/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Pairing chart and selected counts for one technique or intent. */
import { useState } from "react";
import { Grid, Stack, Text } from "@kui/react";
import type { AxisGroup } from "../../utils/techniqueIntentRollup";
import TaxonomyCellChart from "./TaxonomyCellChart";
import CellDetail from "./TechniqueIntentCellDetail";

interface Props {
  group: AxisGroup;
  childNoun: string;
  isDark?: boolean;
  onProbeSelect?: (probe: string) => void;
}
const TechniqueIntentGroupDetail = ({ group, childNoun, isDark, onProbeSelect }: Props) => {
  const [selected, setSelected] = useState<string | null>(
    group.cells.length === 1 ? group.cells[0].otherKey : null
  );
  const entry = group.cells.find(item => item.otherKey === selected);
  return (
    <Stack gap="density-md" paddingY="density-sm">
      <Text kind="label/regular/md" className="opacity-60">
        Pass rate by {childNoun}. Click a bar for the pass/fail breakdown.
      </Text>
      <Grid cols={{ base: 1, md: entry ? 2 : 1 }} gap="density-lg" className="items-start">
        <TaxonomyCellChart
          cells={group.cells}
          isDark={isDark}
          selectedKey={selected}
          onSelect={setSelected}
        />
        {entry && (
          <CellDetail cell={entry.cell} title={entry.otherLabel} onProbeSelect={onProbeSelect} />
        )}
      </Grid>
    </Stack>
  );
};
export default TechniqueIntentGroupDetail;
