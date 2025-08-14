import useSeverityColor from "../hooks/useSeverityColor";

interface DefconBadgeProps {
  defcon: number | null | undefined;
  size?: "sm" | "md" | "lg" | "xl";
  showLabel?: boolean;
}

const DefconBadge = ({ defcon, size = "sm", showLabel = false }: DefconBadgeProps) => {
  const { getDefconColor, getSeverityLabelByLevel } = useSeverityColor();
  
  if (defcon == null || defcon === 0) {
    return (
      <span className={`inline-flex items-center bg-gray-200 text-gray-600 rounded-sm font-medium ${
        size === "sm" ? "px-1.5 py-0.5 text-xs" : 
        size === "md" ? "px-2 py-1 text-sm" : 
        size === "lg" ? "px-3 py-1.5 text-base" :
        "px-3 py-1.5 text-lg"
      }`}>
        N/A
      </span>
    );
  }

  const color = getDefconColor(defcon);
  const label = getSeverityLabelByLevel(defcon);

  return (
    <span 
      className={`inline-flex items-center text-white rounded-sm font-medium ${
        size === "sm" ? "px-1.5 py-0.5 text-xs" : 
        size === "md" ? "px-2 py-1 text-sm" : 
        size === "lg" ? "px-3 py-1.5 text-base" :
        "px-3 py-1.5 text-lg"
      }`}
      style={{ backgroundColor: color }}
      title={`DEFCON ${defcon}: ${label}`}
    >
      DC-{defcon}
      {showLabel && <span className="ml-1">{label}</span>}
    </span>
  );
};

export default DefconBadge; 