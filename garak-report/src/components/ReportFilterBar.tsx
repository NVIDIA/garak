/**
 * @file ReportFilterBar.tsx
 * @description Filter and sort controls for the report module list.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Flex, Text, Group, SegmentedControl } from "@kui/react";
import DefconBadge from "./DefconBadge";
import { DEFCON_LEVELS } from "../constants";
import type { SortOption } from "../hooks/useModuleFilters";

/**
 * Type guard to check if a string is a valid SortOption.
 * @param value - String to check
 * @returns True if value is "defcon" or "alphabetical"
 */
function isSortOption(value: string): value is SortOption {
  return value === "defcon" || value === "alphabetical";
}

/** Props for ReportFilterBar component */
interface ReportFilterBarProps {
  /** Currently selected DEFCON levels */
  selectedDefcons: number[];
  /** Toggle a DEFCON level filter */
  onToggleDefcon: (defcon: number) => void;
  /** Current sort option */
  sortBy: SortOption;
  /** Set the sort option */
  onSortChange: (sort: SortOption) => void;
}

/**
 * Filter bar for DEFCON level filtering and sort option selection.
 *
 * @param props - Component props
 * @returns Filter bar with DEFCON badges and sort control
 */
const ReportFilterBar = ({
  selectedDefcons,
  onToggleDefcon,
  sortBy,
  onSortChange,
}: ReportFilterBarProps) => {
  return (
    <Flex
      gap="density-2xl"
      paddingY="density-lg"
      paddingX="density-lg"
      align="center"
      justify="between"
      wrap="wrap"
    >
      <Flex gap="density-sm" align="center">
        <Text kind="label/bold/md">Filter by DEFCON:</Text>
        <Group kind="gap">
          {DEFCON_LEVELS.map(defcon => {
            const isSelected = selectedDefcons.includes(defcon);
            return (
              <button
                key={defcon}
                onClick={() => onToggleDefcon(defcon)}
                style={{ opacity: isSelected ? 1 : 0.3, cursor: "pointer" }}
                title={`DEFCON ${defcon}. Click to ${isSelected ? "hide" : "show"}.`}
              >
                <DefconBadge defcon={defcon} size="sm" />
              </button>
            );
          })}
        </Group>
      </Flex>

      <Flex gap="density-sm" align="center">
        <Text kind="label/bold/md">Sort by:</Text>
        <SegmentedControl
          size="small"
          value={sortBy}
          onValueChange={value => {
            if (isSortOption(value)) {
              onSortChange(value);
            }
          }}
          items={[
            { children: "DEFCON", value: "defcon" },
            { children: "Alphabetical", value: "alphabetical" },
          ]}
        />
      </Flex>
    </Flex>
  );
};

export default ReportFilterBar;

