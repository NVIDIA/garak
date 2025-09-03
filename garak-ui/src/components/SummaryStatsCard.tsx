import { useMemo } from "react";
import DefconBadge from "./DefconBadge";
import type { ModuleData } from "../types/Module";
import { Notification, Flex, Text, Stack } from "@kui/react";

interface SummaryStatsCardProps {
  modules: ModuleData[];
}

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
    
    const alertLevel = critical.length > 0 ? 1 : 
                      poor.length > 0 ? 2 : 
                      needsAttention.length > totalModules * 0.5 ? 3 : 4;

    return {
      concerning,
      totalModules,
      concerningPercentage,
      alertLevel,
      critical: critical.length,
      poor: poor.length
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
      style={{ maxWidth: "600px" }}
      slotHeading="Security Status"
      slotSubheading={
        <Stack gap="density-sm">
          <Text kind="title/sm">{mainStatusText}</Text>
        </Stack>
      }
      slotFooter={
        hasIssues && (summary.critical > 0 || summary.poor > 0) && (
          <Flex justify="end" gap="density-3xl">
            {summary.critical > 0 && (
              <Flex align="center" gap="density-xs">
                <DefconBadge defcon={1} size="sm" />
                <span className="text-sm font-medium">
                  {summary.critical} Critical
                </span>
              </Flex>
            )}
            {summary.poor > 0 && (
              <Flex align="center" gap="density-xs">
                <DefconBadge defcon={2} size="sm" />
                <span className="text-sm font-medium">
                  {summary.poor} Poor
                </span>
              </Flex>
            )}
          </Flex>
        )
      }
    />
  );
};

export default SummaryStatsCard; 