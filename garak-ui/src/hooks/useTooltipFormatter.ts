import { useZScoreHelpers } from "../hooks/useZScoreHelpers";

export function useTooltipFormatter() {
  const { formatZ } = useZScoreHelpers();

  return function formatTooltip({ data, detectorType }: { data: any; detectorType: string }) {
    const score = data?.detector_score != null ? `${data.detector_score.toFixed(2)}%` : "—";
    const z = formatZ(data?.zscore ?? null);
    const comment = data?.comment ?? "Unavailable";
    const attempts = data?.attempt_count;
    const hits = data?.hit_count ?? data?.fail_count; // whichever makes sense
    const countsLine = attempts != null && hits != null ? `<br/>Attempts: ${attempts}, Detected: ${hits}` : "";
    const color = data?.itemStyle?.color ?? "#666";
    
    // Add DEFCON information
    const defcon = data?.detector_defcon;
    const defconLine = defcon != null ? `<br/>DEFCON: <strong>DC-${defcon}</strong>` : "";

    return `
      <strong>${detectorType}</strong><br/>
      Score: ${score}<br/>
      Z-score: ${z}<br/>
      Comment: <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: ${color}; margin-right: 6px; vertical-align: middle;"></span>${comment}${defconLine}${countsLine}
    `;
  };
}
