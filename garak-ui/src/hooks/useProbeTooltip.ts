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
      return `
      <strong>${params.name}</strong><br/>
      Score: ${params.value.toFixed(2)}%<br/>
      Severity: ${item?.severity ?? "?"} (${item?.severityLabel ?? "Unknown"})
    `;
    },
    [probesData]
  );
}
