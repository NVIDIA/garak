import { useMemo } from "react";
import type { SetupSectionProps } from "../types/SetupSection";
import { useValueFormatter } from "../hooks/useValueFormatter";
import { Tabs, Text, Stack, Flex } from "@kui/react";

type GroupedSections = Record<string, Record<string, unknown>>;

const SetupSection = ({ setup }: SetupSectionProps) => {
  const { formatValue } = useValueFormatter();

  const groupedSections = useMemo(() => {
    if (!setup) return {};
    return Object.entries(setup).reduce<GroupedSections>((acc, [key, value]) => {
      const [category, field] = key.split(".");
      if (!category || !field) return acc;
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
                const display = formatValue(val);

                return isArray ? (
                  <Stack key={key} gap="density-xs">
                    <Text kind="label/bold/sm">
                      {key.replace(/_/g, " ")}:
                    </Text>
                    <Stack gap="density-xs">
                      {(val as any[]).map((item, index) => (
                        <Flex align="center">
                          <i className="nv-icons-line-chevron-right"></i>
                          <Text key={index} kind="body/regular/sm">{formatValue(item)}</Text>
                        </Flex>
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
          )
        };
      })}
    />
  );
};

export default SetupSection;
