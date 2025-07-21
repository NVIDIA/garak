import { useCallback } from "react";
import type { Probe } from "../types/ProbesChart";

export function useProbeTooltip(
  probesData: (Probe & {
    label: string;
    value: number;
    color: string;
    severity?: number;
    severityLabel?: string;
  })[]
) {
  return useCallback(
    (params: any): string => {
      const item = probesData.find(p => p.label === params.name);

      const severityColor = item?.color ?? "#999";
      const severityText = item?.severityLabel ?? "Unknown";

      return `
        <strong>${params.name}</strong><br/>
        Score: ${params.value.toFixed(2)}%<br/>
        Severity: <span style="color: ${severityColor}; font-weight: 600">${severityText}</span><br/>
        Detectors: ${item?.detectors.length ?? 0}
      `;
    },
    [probesData]
  );
}
