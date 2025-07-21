import { useZScoreHelpers } from "../hooks/useZScoreHelpers";

export function useTooltipFormatter() {
  const { formatZ } = useZScoreHelpers();

  return function formatTooltip({ data, detectorType }: { data: any; detectorType: string }) {
    const score = data?.detector_score != null ? `${data.detector_score.toFixed(2)}%` : "—";
    const z = formatZ(data?.zscore ?? null);
    const comment = data?.comment ?? "Unavailable";
    const color = data?.itemStyle?.color ?? "#666";

    return `
      <strong>${detectorType}</strong><br/>
      Score: ${score}<br/>
      Z-score: ${z}<br/>
      Comment: <span style="color:${color}">${comment}</span>
    `;
  };
}
