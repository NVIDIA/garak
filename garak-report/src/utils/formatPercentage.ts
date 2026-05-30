/**
 * @file formatPercentage.ts
 * @description Utility for formatting percentages with smart decimal display.
 * @module utils
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Formats a percentage value, showing decimals only when meaningful.
 * - 56.00 → "56%"
 * - 18.82 → "18.82%"
 * - 100.00 → "100%"
 *
 * @param value - Percentage value (0-100)
 * @param decimals - Number of decimal places (default: 2)
 * @returns Formatted percentage string with % suffix
 *
 * @example
 * ```ts
 * formatPercentage(56.00) // "56%"
 * formatPercentage(18.82) // "18.82%"
 * formatPercentage(0.188 * 100) // "18.80%"
 * ```
 */
export function formatPercentage(value: number, decimals: number = 2): string {
  const formatted = value.toFixed(decimals);
  const suffix = ".".padEnd(decimals + 1, "0"); // ".00" for decimals=2
  return formatted.endsWith(suffix) ? `${Math.round(value)}%` : `${formatted}%`;
}

/**
 * Formats a decimal rate (0-1) as a percentage.
 *
 * @param rate - Rate value (0-1)
 * @param decimals - Number of decimal places (default: 2)
 * @returns Formatted percentage string with % suffix
 *
 * @example
 * ```ts
 * formatRate(0.56) // "56%"
 * formatRate(0.1882) // "18.82%"
 * ```
 */
export function formatRate(rate: number, decimals: number = 2): string {
  return formatPercentage(rate * 100, decimals);
}
