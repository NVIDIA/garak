/**
 * @file useSeverityColor.ts
 * @description Hook providing color mapping functions for DEFCON and severity levels.
 *              Centralizes all color logic for consistent visualization across the app.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useCallback } from "react";
import {
  CSS_COLOR_VARS,
  DEFCON_LABELS,
  DEFCON_RISK_COMMENTS,
  DEFCON_BADGE_COLORS,
  type BadgeColor,
} from "../constants";

/** Valid DEFCON level keys (1-5) */
type DefconKey = 1 | 2 | 3 | 4 | 5;

/**
 * Type guard to check if a number is a valid DEFCON key.
 * @param level - Number to check
 * @returns True if level is 1-5
 */
function isDefconKey(level: number | null | undefined): level is DefconKey {
  return typeof level === "number" && level >= 1 && level <= 5;
}

/**
 * Type guard to check if a string is a valid SortOption.
 * @param value - String to check
 * @returns True if value is a valid BadgeColor
 */
function isBadgeColor(value: string): value is BadgeColor {
  return ["blue", "gray", "green", "purple", "red", "teal", "yellow"].includes(value);
}

/**
 * Retrieves a CSS custom property value from the document root.
 *
 * @param colorVar - CSS variable name (e.g., "--color-red-700")
 * @returns The computed color value, or empty string if unavailable
 */
const getCSSColor = (colorVar: string): string => {
  if (typeof window === "undefined") return "";
  return getComputedStyle(document.documentElement).getPropertyValue(colorVar).trim();
};

/**
 * Provides color mapping functions for severity levels and DEFCON ratings.
 *
 * Centralizes all color logic to ensure consistent visual representation across
 * charts, badges, and text. Supports both numeric severity levels (1-5) and
 * text-based comments ("critical risk", "poor performance", etc.).
 *
 * @returns Object containing color mapping functions for different contexts
 *
 * @example
 * ```tsx
 * const { getSeverityColorByLevel, getDefconColor } = useSeverityColor();
 * const color = getSeverityColorByLevel(3); // Returns yellow for DC-3
 * const badgeColor = getDefconBadgeColor(1); // Returns "red" for DC-1
 * ```
 */
const useSeverityColor = () => {
  const getSeverityColorByLevel = useCallback((severity: number): string => {
    const varName = isDefconKey(severity)
      ? CSS_COLOR_VARS.severity[severity]
      : CSS_COLOR_VARS.severity.default;
    return getCSSColor(varName);
  }, []);

  const getSeverityColorByComment = useCallback((comment: string | null | undefined): string => {
    const commentLower = comment?.toLowerCase() || "";
    // Match the RELATIVE_COMMENT values from garak/analyze/__init__.py
    if (commentLower.includes(DEFCON_RISK_COMMENTS.critical))
      return getCSSColor(CSS_COLOR_VARS.severity[1]);
    if (commentLower.includes(DEFCON_RISK_COMMENTS.veryHigh))
      return getCSSColor(CSS_COLOR_VARS.severity[2]);
    if (commentLower.includes(DEFCON_RISK_COMMENTS.elevated))
      return getCSSColor(CSS_COLOR_VARS.severity[3]);
    if (commentLower.includes(DEFCON_RISK_COMMENTS.medium))
      return getCSSColor(CSS_COLOR_VARS.severity[4]);  // DC-4 = Medium Risk
    if (commentLower.includes(DEFCON_RISK_COMMENTS.low))
      return getCSSColor(CSS_COLOR_VARS.severity[5]);
    // Legacy fallbacks (kept for backwards compatibility)
    if (commentLower.includes(DEFCON_RISK_COMMENTS.veryPoor))
      return getCSSColor(CSS_COLOR_VARS.severity[1]);
    if (commentLower.includes(DEFCON_RISK_COMMENTS.poor))
      return getCSSColor(CSS_COLOR_VARS.severity[1]);
    if (commentLower.includes(DEFCON_RISK_COMMENTS.belowAverage))
      return getCSSColor(CSS_COLOR_VARS.severity[2]);
    if (commentLower.includes(DEFCON_RISK_COMMENTS.average))
      return getCSSColor(CSS_COLOR_VARS.severity[3]);
    if (commentLower.includes(DEFCON_RISK_COMMENTS.aboveAverage))
      return getCSSColor(CSS_COLOR_VARS.severity[3]);
    if (commentLower.includes(DEFCON_RISK_COMMENTS.excellent))
      return getCSSColor(CSS_COLOR_VARS.severity[5]);
    if (commentLower.includes(DEFCON_RISK_COMMENTS.competitive))
      return getCSSColor(CSS_COLOR_VARS.severity[5]);
    return getCSSColor(CSS_COLOR_VARS.severity.default);
  }, []);

  const getDefconColor = useCallback((defcon: number | null | undefined): string => {
    const varName = isDefconKey(defcon) ? CSS_COLOR_VARS.defcon[defcon] : CSS_COLOR_VARS.defcon[4];
    return getCSSColor(varName);
  }, []);

  const getSeverityLabelByLevel = useCallback((defcon: number | null | undefined): string => {
    return isDefconKey(defcon) ? DEFCON_LABELS[defcon] : DEFCON_LABELS.default;
  }, []);

  const getDefconBadgeColor = useCallback((level: number): BadgeColor => {
    if (isDefconKey(level)) {
      const color = DEFCON_BADGE_COLORS[level];
      if (isBadgeColor(color)) return color;
    }
    const defaultColor = DEFCON_BADGE_COLORS.default;
    return isBadgeColor(defaultColor) ? defaultColor : "gray";
  }, []);

  return {
    getSeverityColorByLevel,
    getSeverityColorByComment,
    getDefconColor,
    getSeverityLabelByLevel,
    getDefconBadgeColor,
  };
};

export default useSeverityColor;
