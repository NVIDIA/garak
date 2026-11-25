/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useState } from "react";
import Heatmap from "../TechniqueIntentHeatmap";
import type { MatrixView } from "../../../utils/techniqueIntentRollup";
import type { HeatmapSelection } from "../../../types/TechniqueIntentHeatmap";
const TestHeatmap = ({
  view,
  onSelect = () => {},
  onProbeSelect,
}: {
  view: MatrixView;
  onSelect?: (next: HeatmapSelection | null) => void;
  onProbeSelect?: (probe: string) => void;
}) => {
  const [selection, setSelection] = useState<HeatmapSelection | null>(null);
  return (
    <Heatmap
      view={view}
      selection={selection}
      onProbeSelect={onProbeSelect}
      onSelectionChange={next => {
        setSelection(next);
        onSelect(next);
      }}
    />
  );
};

export default TestHeatmap;
