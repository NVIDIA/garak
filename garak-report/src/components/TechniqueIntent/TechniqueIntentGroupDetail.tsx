/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Pairing chart and selected counts for one technique or intent. */
import { useMemo, useState } from "react";
import { Button, Grid, Stack, Text } from "@kui/react";
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
  const { measured, undetermined } = useMemo(
    () => ({
      measured: group.cells.filter(item => item.cell.score != null),
      undetermined: group.cells.filter(item => item.cell.score == null),
    }),
    [group.cells]
  );
  return (
    <Stack gap="density-md" paddingY="density-sm">
      {measured.length > 0 && (
        <Text kind="label/regular/md" className="opacity-60">
          Pass rate by {childNoun}. Click a bar for the pass/fail breakdown.
        </Text>
      )}
      <Grid cols={{ base: 1, md: entry ? 2 : 1 }} gap="density-lg" className="items-start">
        <Stack gap="density-sm">
          {measured.length > 0 && (
            <TaxonomyCellChart
              cells={measured}
              isDark={isDark}
              selectedKey={selected}
              onSelect={setSelected}
            />
          )}
          {undetermined.length > 0 && (
            <>
              <Text kind="label/regular/sm">Undetermined pairings</Text>
              {undetermined.map(item => (
                <Button
                  key={item.otherKey}
                  kind="secondary"
                  color="neutral"
                  onClick={() => setSelected(selected === item.otherKey ? null : item.otherKey)}
                >
                  {item.otherLabel}
                </Button>
              ))}
            </>
          )}
        </Stack>
        {entry && (
          <CellDetail cell={entry.cell} title={entry.otherLabel} onProbeSelect={onProbeSelect} />
        )}
      </Grid>
    </Stack>
  );
};
export default TechniqueIntentGroupDetail;
