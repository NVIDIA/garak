/**
 * @file DefconBadge.tsx
 * @description Badge component displaying DEFCON level with appropriate coloring.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import useSeverityColor from "../hooks/useSeverityColor";
import { Badge } from "@kui/react";

/** Props for DefconBadge component */
interface DefconBadgeProps {
  defcon: number | null | undefined;
  size?: "sm" | "md" | "lg" | "xl"; // kept for compatibility but not used with Kaizen Badge
  showLabel?: boolean;
}

/**
 * Badge displaying DEFCON level (1-5) with color coding.
 * Shows "N/A" for null/undefined/zero values.
 *
 * @param props - Component props
 * @param props.defcon - DEFCON level (1-5) or null
 * @param props.showLabel - Whether to show text label after level
 * @returns Colored badge with DEFCON indicator
 */
const DefconBadge = ({ defcon, showLabel = false }: DefconBadgeProps) => {
  const { getSeverityLabelByLevel, getDefconBadgeColor } = useSeverityColor();
  const color = getDefconBadgeColor(defcon ?? 0);
  const label = getSeverityLabelByLevel(defcon ?? 0);

  if (defcon == null || defcon === 0) {
    return (
      <Badge kind="outline" color="gray">
        N/A
      </Badge>
    );
  }

  return (
    <Badge kind="solid" color={color} title={`DEFCON ${defcon}: ${label}`}>
      DC-{defcon}
      {showLabel && <span className="ml-1">{label}</span>}
    </Badge>
  );
};

export default DefconBadge;
