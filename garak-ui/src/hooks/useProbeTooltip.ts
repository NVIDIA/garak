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
      
      // Map severity to DEFCON (severity is essentially the same as DEFCON level)
      const defcon = item?.severity;
      const defconLine = defcon != null ? `<br/>DEFCON: <strong>DC-${defcon}</strong>` : "";

      return `
        <strong>${params.name}</strong><br/>
        Score: ${params.value.toFixed(2)}%<br/>
        Severity: <span style="display: inline-block; width: 8px; height: 8px; border-radius: 50%; background-color: ${severityColor}; margin-right: 6px; vertical-align: middle;"></span><span style="font-weight: 600">${severityText}</span>${defconLine}<br/>
        Detectors: ${item?.detectors.length ?? 0}
      `;
    },
    [probesData]
  );
}
