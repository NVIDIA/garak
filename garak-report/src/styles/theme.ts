/**
 * @file theme.ts
 * @description Legacy theme object with hardcoded color values.
 *              Used as fallback when CSS variables are not available.
 * @module styles
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/**
 * Legacy color palette for chart elements and fallback styling.
 * Prefer CSS variables from constants/theme.ts for theming support.
 */
const theme = {
  colors: {
    /** Light blue - informational elements */
    b400: "#60a5fa",
    /** Light green - success/low risk */
    g400: "#4ade80",
    /** Dark green - strong success */
    g700: "#15803d",
    /** Yellow - warnings/medium risk */
    y300: "#facc15",
    /** Orange-yellow - elevated warnings */
    y400: "#fbbf24",
    /** Light red - high risk */
    r400: "#f87171",
    /** Dark red - critical risk */
    r600: "#dc2626",
    /** Darker red - severe critical */
    r700: "#b91c1c",
    /** Default grey - unavailable/neutral */
    tk150: "#9ca3af",
  },
};

export default theme;
