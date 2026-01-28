/**
 * @file useValueFormatter.ts
 * @description Hook providing generic value formatting for display.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Provides a generic value formatter for displaying configuration values.
 *
 * @returns Object with formatValue function
 *
 * @example
 * ```tsx
 * const { formatValue } = useValueFormatter();
 * formatValue(['a', 'b']);    // "a, b"
 * formatValue(true);          // "Enabled"
 * formatValue(null);          // "N/A"
 * ```
 */
export const useValueFormatter = () => {
  /**
   * Formats a value for display in the UI.
   *
   * @param value - Any value to format
   * @returns Human-readable string representation
   */
  const formatValue = (value: unknown): string => {
    if (Array.isArray(value)) return value.join(", ");
    if (typeof value === "boolean") return value ? "Enabled" : "Disabled";
    if (value == null) return "N/A";
    return String(value);
  };

  return { formatValue };
};
