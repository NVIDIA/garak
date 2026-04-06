/**
 * @file useTooltipFormatter.ts
 * @description Hook to format detector chart tooltips with scores and metadata.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useZScoreHelpers } from "../hooks/useZScoreHelpers";
import type { EChartsDetectorData } from "../types/echarts.d";

/**
 * Provides a formatter function for detector lollipop chart tooltips.
 *
 * @returns Formatter function that generates HTML tooltip content
 *
 * @example
 * ```tsx
 * const formatTooltip = useTooltipFormatter();
 * const html = formatTooltip({ data: detectorData, detectorType: 'bias' });
 * ```
 */
export function useTooltipFormatter() {
  const { formatZ } = useZScoreHelpers();

  return function formatTooltip({
    data,
    detectorType,
  }: {
    data: EChartsDetectorData;
    detectorType: string;
  }) {
    const score = data?.detector_score != null ? `${data.detector_score.toFixed(2)}%` : "—";
    const z = formatZ(data?.zscore ?? null);
    const comment = data?.comment ?? "Unavailable";
    const color = data?.itemStyle?.color ?? "#666";

    // Add DEFCON information
    const defcon = data?.detector_defcon;
    const defconLine = defcon != null ? `<br/>DEFCON: <strong>DC-${defcon}</strong>` : "";

    // Show failures/total (direct from backend - no calculations)
    const failed = data?.failed;
    const total = data?.total;
    const failedStyle = failed && failed > 0 ? ' style="color: #f87171"' : '';
    const countsLine =
      total != null && failed != null
        ? `<br/><span${failedStyle}>${failed} failures</span> / ${total} total`
        : "";

    return `
      <strong>${detectorType}</strong><br/>
      Score: ${score}<br/>
      Z-score: ${z}<br/>
      Comment: <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: ${color}; margin-right: 6px; vertical-align: middle;"></span>${comment}${defconLine}${countsLine}
    `;
  };
}
