import useSeverityColor from "../hooks/useSeverityColor";

const levels = [1, 2, 3, 4, 5];

const ColorLegend = ({ onClose }: { onClose?: () => void }) => {
  const { getSeverityColorByLevel, getSeverityLabelByLevel } = useSeverityColor();

  return (
    <div className="flex items-center gap-3 flex-wrap text-xs mt-1 bg-white p-2 border rounded shadow">
      {levels.map(l => (
        <div key={l} className="flex items-center gap-1">
          <span
            style={{ background: getSeverityColorByLevel(l), width: 14, height: 14, display: "inline-block" }}
            aria-label={getSeverityLabelByLevel(l)}
          />
          <span className="text-gray-700 select-none">{getSeverityLabelByLevel(l)}</span>
        </div>
      ))}
      {onClose && (
        <button
          onClick={onClose}
          className="ml-auto text-gray-500 hover:text-gray-700 px-1"
          aria-label="Hide legend"
        >
          ×
        </button>
      )}
    </div>
  );
};

export default ColorLegend; 