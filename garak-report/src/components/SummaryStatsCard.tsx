/**
 * @file SummaryStatsCard.tsx
 * @description Security status notification card showing overall report health.
 *              Displays DEFCON breakdown and highlights critical/high-risk modules.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import DefconBadge from "./DefconBadge";
import type { ModuleData } from "../types/Module";
import { Notification, Flex, Text, Stack } from "@kui/react";

/** Props for SummaryStatsCard component */
interface SummaryStatsCardProps {
  modules: ModuleData[];
}

/**
 * Summary notification card showing overall security status.
 * Calculates alert level based on module DEFCON distribution.
 *
 * @param props - Component props
 * @param props.modules - Array of module data to summarize
 * @returns Status notification with risk breakdown
 */
const SummaryStatsCard = ({ modules }: SummaryStatsCardProps) => {
  const summary = useMemo(() => {
    if (!modules.length) return null;

    const concerning = modules.filter(m => m.summary.group_defcon <= 2);
    const totalModules = modules.length;
    const concerningPercentage = (concerning.length / totalModules) * 100;

    // Determine alert level based on failures
    const critical = modules.filter(m => m.summary.group_defcon === 1);
    const poor = modules.filter(m => m.summary.group_defcon === 2);
    const needsAttention = modules.filter(m => m.summary.group_defcon <= 3);

    const alertLevel =
      critical.length > 0
        ? 1
        : poor.length > 0
          ? 2
          : needsAttention.length > totalModules * 0.5
            ? 3
            : 4;

    return {
      concerning,
      totalModules,
      concerningPercentage,
      alertLevel,
      critical: critical.length,
      poor: poor.length,
    };
  }, [modules]);

  if (!summary || summary.totalModules === 0) {
    return null;
  }

  const hasIssues = summary.concerning.length > 0;

  // Determine notification status based on alert level
  const getNotificationStatus = () => {
    if (summary.alertLevel === 1) return "error";
    if (summary.alertLevel === 2) return "warning";
    if (summary.alertLevel === 3) return "info";
    return "success";
  };

  const mainStatusText = hasIssues
    ? `${summary.concerning.length}/${summary.totalModules} modules are below DC-3`
    : `${summary.totalModules} modules evaluated - all secure`;

  return (
    <Notification
      status={getNotificationStatus()}
      density="spacious"
      slotHeading="Security Status"
      slotSubheading={
        <Stack gap="density-lg">
          <Text kind="title/md">{mainStatusText}</Text>
        </Stack>
      }
      slotFooter={
        hasIssues &&
        (summary.critical > 0 || summary.poor > 0) && (
          <Flex justify="end" gap="density-xl" wrap="wrap">
            {summary.critical > 0 && (
              <Flex align="center" gap="density-sm">
                <DefconBadge defcon={1} size="sm" />
                <Text kind="body/bold/sm">{summary.critical} Critical Risk</Text>
              </Flex>
            )}
            {summary.poor > 0 && (
              <Flex align="center" gap="density-sm">
                <DefconBadge defcon={2} size="sm" />
                <Text kind="body/bold/sm">{summary.poor} Very High Risk</Text>
              </Flex>
            )}
          </Flex>
        )
      }
    />
  );
};

export default SummaryStatsCard;
