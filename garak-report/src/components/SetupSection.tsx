/**
 * @file SetupSection.tsx
 * @description Tabbed display of Garak configuration settings grouped by category.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import type { SetupSectionProps } from "../types/SetupSection";
import { useValueFormatter } from "../hooks/useValueFormatter";
import { Tabs, Text, Stack, Flex } from "@kui/react";

/** Grouped configuration sections by category */
type GroupedSections = Record<string, Record<string, unknown>>;

/**
 * Displays Garak configuration in categorized tabs.
 * Groups settings by prefix (e.g., "plugins", "reporting") and formats values.
 *
 * @param props - Component props
 * @param props.setup - Configuration key-value pairs
 * @returns Tabbed configuration display grouped by category
 */
const SetupSection = ({ setup }: SetupSectionProps) => {
  const { formatValue } = useValueFormatter();

  const groupedSections = useMemo(() => {
    if (!setup) return {};
    return Object.entries(setup).reduce<GroupedSections>((acc, [key, value]) => {
      const [category, field] = key.split(".");
      if (!category || !field) return acc;
      // For _config category, only include config_files
      if (category === "_config" && field !== "config_files") return acc;
      if (!acc[category]) acc[category] = {};
      acc[category][field] = value;
      return acc;
    }, {});
  }, [setup]);

  const sectionKeys = Object.keys(groupedSections);

  if (sectionKeys.length === 0) return null;

  return (
    <Tabs
      items={sectionKeys.map(section => {
        const fields = groupedSections[section];

        return {
          value: section,
          children: section.replace(/_/g, " "),
          slotContent: (
            <Stack gap="density-xl">
              {Object.entries(fields).map(([key, val]) => {
                const isArray = Array.isArray(val);
                const isSpecField = key.toLowerCase().includes("spec") && typeof val === "string";
                const display = formatValue(val);

                // Handle spec fields as comma-separated lists
                if (isSpecField) {
                  const specItems = (val as string)
                    .split(",")
                    .map(s => s.trim())
                    .filter(Boolean);
                  return (
                    <Stack key={key} gap="density-xs">
                      <Text kind="label/bold/sm">{key.replace(/_/g, " ")}:</Text>
                      <Stack gap="density-xs">
                        {specItems.map((item, index) => (
                          <Text key={index} kind="body/regular/sm">
                            {item}
                          </Text>
                        ))}
                      </Stack>
                    </Stack>
                  );
                }

                return isArray ? (
                  <Stack key={key} gap="density-xs">
                    <Text kind="label/bold/sm">{key.replace(/_/g, " ")}:</Text>
                    <Stack gap="density-xs">
                      {(val as unknown[]).map((item, index) => (
                        <Text key={index} kind="body/regular/sm">
                          {formatValue(item)}
                        </Text>
                      ))}
                    </Stack>
                  </Stack>
                ) : (
                  <Flex key={key} gap="density-xs" align="baseline">
                    <Text kind="label/bold/sm" className="whitespace-nowrap">
                      {key.replace(/_/g, " ")}:
                    </Text>
                    <Text
                      kind="body/regular/sm"
                      className="flex-1"
                      title={typeof display === "string" ? display : ""}
                    >
                      {display}
                    </Text>
                  </Flex>
                );
              })}
            </Stack>
          ),
        };
      })}
    />
  );
};

export default SetupSection;
