/**
 * @file ModuleAccordion.tsx
 * @description Accordion component displaying module list with expandable probe charts.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useState } from "react";
import { Accordion, Anchor, Badge, Flex, Stack, Text } from "@kui/react";
import ErrorBoundary from "./ErrorBoundary";
import ProbesChart from "./ProbesChart";
import useSeverityColor from "../hooks/useSeverityColor";
import type { ModuleData } from "../types/Module";
import type { Probe } from "../types/ProbesChart";

/** Props for ModuleAccordion component */
interface ModuleAccordionProps {
  /** Modules to display in accordion */
  modules: ModuleData[];
  /** Unique key for accordion reset (e.g., report UUID) */
  accordionKey: string;
  /** Whether dark theme is active */
  isDark: boolean;
}

/**
 * Accordion displaying modules with expandable probe charts.
 * Shows module score, DEFCON level, and description in trigger.
 *
 * @param props - Component props
 * @returns Accordion with module list and expandable charts
 */
const ModuleAccordion = ({ modules, accordionKey, isDark }: ModuleAccordionProps) => {
  const [selectedProbe, setSelectedProbe] = useState<Probe | null>(null);
  const [openAccordionValue, setOpenAccordionValue] = useState<string>("");
  const { getDefconBadgeColor } = useSeverityColor();

  return (
    <Accordion
      key={accordionKey}
      value={openAccordionValue}
      items={modules.map(module => ({
        slotTrigger: (
          <Flex direction="row" gap="density-lg">
            <Flex direction="col" gap="density-sm">
              <Badge
                color={getDefconBadgeColor(module.summary.group_defcon)}
                kind="solid"
                className="w-[70px]"
              >
                <Text kind="label/bold/xl">{(module.summary.score * 100).toFixed(0)}%</Text>
              </Badge>
              <Badge
                color={getDefconBadgeColor(module.summary.group_defcon)}
                kind="outline"
                className="w-[70px]"
              >
                <Text kind="label/bold/md">DC-{module.summary.group_defcon}</Text>
              </Badge>
            </Flex>
            <Stack align="start" gap="density-md">
              <Text kind="label/bold/2xl">{module.group_name}</Text>
              <Anchor
                href={module.summary.group_link}
                target="_blank"
                rel="noopener noreferrer"
              >
                <Text dangerouslySetInnerHTML={{ __html: module.summary.doc }} />
              </Anchor>
            </Stack>
          </Flex>
        ),
        slotContent: (
          <ErrorBoundary fallbackMessage="Failed to load chart for this module.">
            <ProbesChart
              key={`${accordionKey}-${module.group_name}`}
              module={{ ...module, probes: module.probes ?? [] }}
              setSelectedProbe={setSelectedProbe}
              selectedProbe={selectedProbe}
              isDark={isDark}
            />
          </ErrorBoundary>
        ),
        value: module.group_name,
      }))}
      onValueChange={value => {
        setOpenAccordionValue(value as string);
        setSelectedProbe(null);
      }}
    />
  );
};

export default ModuleAccordion;

