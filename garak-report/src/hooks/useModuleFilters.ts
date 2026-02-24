/**
 * @file useModuleFilters.ts
 * @description Hook for filtering and sorting module data by DEFCON level.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useState, useMemo, useCallback } from "react";
import type { ModuleData } from "../types/Module";
import { DEFCON_LEVELS } from "../constants";

/** Sort options for module list */
export type SortOption = "defcon" | "alphabetical";

/**
 * Return type for useModuleFilters hook
 */
export interface ModuleFiltersState {
  /** Filtered and sorted modules */
  modules: ModuleData[];
  /** Currently selected DEFCON levels */
  selectedDefcons: number[];
  /** Current sort option */
  sortBy: SortOption;
  /** Toggle a DEFCON level filter */
  toggleDefcon: (defcon: number) => void;
  /** Set the sort option */
  setSortBy: (sort: SortOption) => void;
}

/**
 * Hook for filtering and sorting modules by DEFCON level.
 *
 * @param allModules - All modules to filter
 * @returns Filter state and filtered/sorted modules
 *
 * @example
 * ```tsx
 * const { modules, selectedDefcons, toggleDefcon } = useModuleFilters(allModules);
 * ```
 */
export function useModuleFilters(allModules: ModuleData[]): ModuleFiltersState {
  const [selectedDefcons, setSelectedDefcons] = useState<number[]>([...DEFCON_LEVELS]);
  const [sortBy, setSortBy] = useState<SortOption>("defcon");

  const toggleDefcon = useCallback((defcon: number) => {
    setSelectedDefcons(prev =>
      prev.includes(defcon) ? prev.filter(d => d !== defcon) : [...prev, defcon].sort()
    );
  }, []);

  const modules = useMemo(() => {
    let filtered = allModules.filter(module =>
      selectedDefcons.includes(module.summary.group_defcon)
    );

    if (sortBy === "defcon") {
      filtered = filtered.sort((a, b) => a.summary.group_defcon - b.summary.group_defcon);
    } else {
      filtered = filtered.sort((a, b) => a.group_name.localeCompare(b.group_name));
    }

    return filtered;
  }, [allModules, selectedDefcons, sortBy]);

  return { modules, selectedDefcons, sortBy, toggleDefcon, setSortBy };
}

