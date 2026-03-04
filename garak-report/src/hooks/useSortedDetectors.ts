/**
 * @file useSortedDetectors.ts
 * @description Hook to sort detectors by Z-score for ordered display.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { Detector } from "../types/ProbesChart";

/**
 * Provides a function to sort detectors by relative score (ascending).
 * Null/undefined scores are sorted to the end.
 *
 * @returns Sort function for detector arrays
 */
export function useSortedDetectors() {
  return function sortDetectors(entries: Detector[]): Detector[] {
    return [...entries].sort((a, b) => {
      if (a.relative_score == null) return 1;
      if (b.relative_score == null) return -1;
      return a.relative_score - b.relative_score;
    });
  };
}
