import useSeverityColor from "../hooks/useSeverityColor";
import { Badge } from "@kui/react";

interface DefconBadgeProps {
  defcon: number | null | undefined;
  size?: "sm" | "md" | "lg" | "xl"; // kept for compatibility but not used with Kaizen Badge
  showLabel?: boolean;
}

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
    <Badge 
      kind="solid" 
      color={color}
      title={`DEFCON ${defcon}: ${label}`}
    >
      DC-{defcon}
      {showLabel && <span className="ml-1">{label}</span>}
    </Badge>
  );
};

export default DefconBadge; 