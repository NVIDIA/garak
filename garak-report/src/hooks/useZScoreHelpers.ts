/**
 * @file useZScoreHelpers.ts
 * @description Utilities for Z-score formatting and clamping in visualizations.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Provides utilities for Z-score formatting and clamping in charts.
 *
 * Z-scores represent how many standard deviations away from the mean a result is.
 * We clamp values to [-3, 3] for visualization purposes since extreme outliers
 * would distort the chart scale.
 *
 * @returns Object with formatZ and clampZ helper functions
 *
 * @example
 * ```tsx
 * const { formatZ, clampZ } = useZScoreHelpers();
 * formatZ(1.234);  // "1.23"
 * formatZ(null);   // "N/A"
 * clampZ(5.0);     // 3 (clamped to max)
 * ```
 */
export const useZScoreHelpers = () => {
  const formatZ = (z: number | null): string => {
    if (z == null) return "N/A";
    if (z <= -3) return "≤ -3.0";
    if (z >= 3) return "≥ 3.0";
    return z.toFixed(2);
  };

  const clampZ = (z: number) => Math.max(-3, Math.min(3, z));

  return { formatZ, clampZ };
};
