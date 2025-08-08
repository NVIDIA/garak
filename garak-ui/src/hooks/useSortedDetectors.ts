import type { Detector } from "../types/ProbesChart";

export function useSortedDetectors() {
  return function sortDetectors(entries: Detector[]): Detector[] {
    return [...entries].sort((a, b) => {
      if (a.zscore == null) return 1;
      if (b.zscore == null) return -1;
      return a.zscore - b.zscore;
    });
  };
}
