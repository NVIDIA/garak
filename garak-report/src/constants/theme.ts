/**
 * @file theme.ts
 * @description Theme-related constants including color palettes, CSS variable
 *              mappings, and badge color definitions for light/dark modes.
 * @module constants
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Static color values for text and chart elements in light/dark themes */
export const THEME_COLORS = {
  text: {
    dark: "#e5e7eb",
    light: "#333",
  },
  chart: {
    splitLine: {
      dark: "#374151",
      light: "#e5e7eb",
    },
  },
} as const;

/**
 * CSS custom property names for DEFCON and severity colors.
 * These map to KUI theme variables for consistent theming.
 */
export const CSS_COLOR_VARS = {
  defcon: {
    1: "--color-red-700",
    2: "--color-yellow-400",
    3: "--color-blue-400", // Blue to match badge color
    4: "--color-green-600",
    5: "--color-teal-400",
  },
  severity: {
    1: "--color-red-200",
    2: "--color-yellow-200",
    3: "--color-blue-200", // Blue to match defcon-3
    4: "--color-green-400",
    5: "--color-teal-200",
    default: "--color-gray-200",
  },
} as const;

/** KUI Badge color names mapped to DEFCON levels */
export const DEFCON_BADGE_COLORS = {
  1: "red",
  2: "yellow",
  3: "blue", // Distinct from DC-4 (green)
  4: "green",
  5: "teal",
  default: "gray",
} as const;

/** Valid KUI Badge color values */
export type BadgeColor = "blue" | "gray" | "green" | "purple" | "red" | "teal" | "yellow";
