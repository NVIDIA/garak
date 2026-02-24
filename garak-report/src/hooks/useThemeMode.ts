/**
 * @file useThemeMode.ts
 * @description Hook for computing and toggling theme mode (light/dark).
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo, useCallback } from "react";
import type { ThemeValue } from "../types/Theme";

// Re-export for backward compatibility
export type { ThemeValue } from "../types/Theme";

/**
 * Return type for useThemeMode hook
 */
export interface ThemeModeState {
  /** Whether current effective theme is dark */
  isDark: boolean;
  /** Toggle between light and dark (ignores system) */
  toggleTheme: () => void;
}

/**
 * Hook for computing effective theme and providing toggle functionality.
 *
 * @param currentTheme - Current theme setting
 * @param onThemeChange - Callback to change theme
 * @returns Computed isDark state and toggle function
 *
 * @example
 * ```tsx
 * const { isDark, toggleTheme } = useThemeMode(currentTheme, onThemeChange);
 * ```
 */
export function useThemeMode(
  currentTheme: ThemeValue,
  onThemeChange?: (theme: ThemeValue) => void
): ThemeModeState {
  const isDark = useMemo(() => {
    if (currentTheme === "dark") return true;
    if (currentTheme === "light") return false;
    // For "system", check actual computed theme
    if (typeof window !== "undefined") {
      return window.matchMedia("(prefers-color-scheme: dark)").matches;
    }
    return false;
  }, [currentTheme]);

  const toggleTheme = useCallback(() => {
    if (onThemeChange) {
      const newTheme = isDark ? "light" : "dark";
      onThemeChange(newTheme);
    }
  }, [isDark, onThemeChange]);

  return { isDark, toggleTheme };
}

