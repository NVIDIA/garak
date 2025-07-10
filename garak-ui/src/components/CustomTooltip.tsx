import useSeverityColor from "../hooks/useSeverityColor";

const CustomTooltip = ({ active, payload }: { active?: boolean; payload?: any }) => {
  const { getSeverityColorByComment } = useSeverityColor();

  if (active && payload && payload.length) {
    const { detector_name, detector_score, zscore, zscore_comment } = payload[0].payload;
    return (
      <div
        style={{
          backgroundColor: "#fff",
          padding: "10px",
          border: "1px solid #ccc",
          borderRadius: "15px",
        }}
      >
        <strong>{detector_name}</strong>
        <p>Score: {detector_score}</p>
        <p>
          Compared to other models:
          <span style={{ color: getSeverityColorByComment(zscore_comment), fontWeight: "bold" }}>
            {" "}
            {zscore_comment} (Z-score: {zscore})
          </span>
        </p>
      </div>
    );
  }
  return null;
};

export default CustomTooltip;
