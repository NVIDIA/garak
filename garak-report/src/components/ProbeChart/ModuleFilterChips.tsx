/**
 * @file ModuleFilterChips.tsx
 * @description Clickable filter chips for filtering probes by module family.
 *              Uses KUI Badge component for consistent styling.
 * @module components/ProbeChart
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Badge, Button, Flex, Stack, Text, Tooltip } from "@kui/react";
import { Info } from "lucide-react";

/** Valid KUI Badge colors */
type KUIBadgeColor = "blue" | "green" | "red" | "yellow" | "purple" | "teal" | "gray";

/** Color rotation for module chips */
const MODULE_COLORS: KUIBadgeColor[] = ["blue", "green", "purple", "teal", "yellow", "red"];

/** CSS variable mapping for dot colors (uses KUI theme variables) */
const DOT_COLOR_VARS: Record<KUIBadgeColor, string> = {
  blue: "var(--color-blue-500)",
  green: "var(--color-green-500)",
  purple: "var(--color-purple-500)",
  teal: "var(--color-teal-500)",
  yellow: "var(--color-yellow-500)",
  red: "var(--color-red-500)",
  gray: "var(--color-gray-500)",
};

/**
 * Gets a consistent color for a module based on its index.
 * Uses modulo to cycle through available colors.
 */
function getModuleColor(index: number): KUIBadgeColor {
  return MODULE_COLORS[index % MODULE_COLORS.length];
}

export interface ModuleFilterChipsProps {
  /** Unique module names to display as chips */
  moduleNames: string[];
  /** Currently selected modules (multi-select) */
  selectedModules: string[];
  /** Callback when a chip is clicked */
  onSelectModule: (moduleName: string) => void;
}

/**
 * Displays clickable filter chips for each probe module.
 * Supports multi-select - click multiple chips to filter by multiple modules.
 * Clicking a selected chip deselects it.
 *
 * @param props - Component props
 * @returns Row of clickable module filter badges
 */
const ModuleFilterChips = ({
  moduleNames,
  selectedModules,
  onSelectModule,
}: ModuleFilterChipsProps) => {
  const isInteractive = moduleNames.length > 1;
  const hasSelection = selectedModules.length > 0;

  return (
    <Stack gap="density-xs" paddingTop="density-sm" paddingBottom="density-md">
      <Flex align="center" gap="density-xxs">
        <Text kind="label/bold/sm">Modules</Text>
        <Tooltip
          slotContent={
            <Stack gap="density-xxs">
              <Text kind="body/regular/sm">
                Modules are probe families that group related security tests.
              </Text>
              {isInteractive && (
                <Text kind="body/regular/sm">
                  Click to filter the chart by module. Multiple selections supported.
                </Text>
              )}
            </Stack>
          }
        >
          <Button kind="tertiary">
            <Info size={14} />
          </Button>
        </Tooltip>
      </Flex>
      <Flex gap="density-xs" wrap="wrap">
      {moduleNames.map((moduleName, index) => {
        const isSelected = selectedModules.includes(moduleName);
        const color = isInteractive ? getModuleColor(index) : "gray";
        const dotColor = DOT_COLOR_VARS[color];

        return (
          <Badge
            key={moduleName}
            color={color}
            kind={isSelected ? "solid" : "outline"}
            onClick={isInteractive ? () => onSelectModule(moduleName) : undefined}
            className={isInteractive ? "cursor-pointer" : ""}
          >
            {isInteractive ? (
              <Flex align="center" gap="density-xxs">
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    backgroundColor: dotColor,
                    flexShrink: 0,
                  }}
                />
                <Text kind="label/bold/sm">{moduleName}</Text>
              </Flex>
            ) : (
              <Text kind="label/bold/sm">{moduleName}</Text>
            )}
          </Badge>
        );
      })}
      {isInteractive && hasSelection && (
        <Badge
          color="gray"
          kind="outline"
          onClick={() => selectedModules.forEach(m => onSelectModule(m))}
          className="cursor-pointer"
        >
          <Text kind="label/regular/sm">Clear all</Text>
        </Badge>
      )}
      </Flex>
    </Stack>
  );
};

export default ModuleFilterChips;
