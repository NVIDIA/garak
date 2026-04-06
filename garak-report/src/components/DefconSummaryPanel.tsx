/**
 * @file DefconSummaryPanel.tsx
 * @description Detailed DEFCON summary cards showing risk breakdown and worst performers.
 *              Displays critical, high-risk, success, and performance overview cards.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import DefconBadge from "./DefconBadge";
import useSeverityColor from "../hooks/useSeverityColor";
import type { ModuleData } from "../types/Module";

/** Props for DefconSummaryPanel component */
interface DefconSummaryPanelProps {
  modules: ModuleData[];
}

/**
 * Renders detailed DEFCON summary cards based on module risk distribution.
 * Shows critical risk, high risk, success state, and performance overview.
 *
 * @param props - Component props
 * @param props.modules - Array of module data to analyze
 * @returns Array of risk summary cards
 */
const DefconSummaryPanel = ({ modules }: DefconSummaryPanelProps) => {
  const { getSeverityColorByLevel } = useSeverityColor();

  const summary = useMemo(() => {
    if (!modules.length) return null;

    // Focus on failures and concerns
    const critical = modules.filter(m => m.summary.group_defcon === 1);
    const poor = modules.filter(m => m.summary.group_defcon === 2);
    const concerning = modules.filter(m => m.summary.group_defcon <= 2);
    const needsAttention = modules.filter(m => m.summary.group_defcon <= 3);

    // Find worst performing modules
    const sortedByScore = [...modules].sort((a, b) => a.summary.score - b.summary.score);
    const worstModules = sortedByScore.slice(0, 3);

    const totalModules = modules.length;
    const concerningPercentage = (concerning.length / totalModules) * 100;
    const needsAttentionPercentage = (needsAttention.length / totalModules) * 100;

    // Determine alert level based on failures
    const alertLevel =
      critical.length > 0
        ? 1
        : poor.length > 0
          ? 2
          : needsAttention.length > totalModules * 0.5
            ? 3
            : 4;

    return {
      critical,
      poor,
      concerning,
      needsAttention,
      worstModules,
      totalModules,
      concerningPercentage,
      needsAttentionPercentage,
      alertLevel,
    };
  }, [modules]);

  if (!summary || summary.totalModules === 0) {
    return null;
  }

  const hasFailures = summary.concerning.length > 0;

  const cards = [];

  // Critical Failures Card
  if (summary.critical.length > 0) {
    cards.push(
      <div
        key="critical"
        className="p-4 rounded-lg border-l-4 bg-red-50"
        style={{ borderColor: getSeverityColorByLevel(1) }}
      >
        <div className="flex items-center gap-4 mb-3">
          <h2 className="text-lg font-semibold text-red-900">🚨 Critical Risk</h2>
          <DefconBadge defcon={1} size="md" showLabel />
        </div>
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="px-2 py-1 rounded bg-red-700 text-white text-sm font-medium">
              {summary.critical.length}
            </div>
            <span className="text-sm text-red-800">
              Module{summary.critical.length !== 1 ? "s" : ""} requiring immediate action
            </span>
          </div>
          <div className="text-xs text-red-600 mt-2 grid grid-cols-3 gap-2">
            {summary.critical.map(module => (
              <div key={module.group_name} className="flex items-center gap-1">
                <DefconBadge defcon={module.summary.group_defcon} size="sm" />
                <span>• {module.group_name}</span>
                <span className="font-medium">({(module.summary.score * 100).toFixed(1)}%)</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Poor Performance Card
  if (summary.poor.length > 0) {
    cards.push(
      <div
        key="poor"
        className="p-4 rounded-lg border-l-4 bg-orange-50"
        style={{ borderColor: getSeverityColorByLevel(2) }}
      >
        <div className="flex items-center gap-4 mb-3">
          <h2 className="text-lg font-semibold text-orange-900">⚡ Very High Risk</h2>
          <DefconBadge defcon={2} size="md" showLabel />
        </div>
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="px-2 py-1 rounded bg-orange-600 text-white text-sm font-medium">
              {summary.poor.length}
            </div>
            <span className="text-sm text-orange-800">
              Module{summary.poor.length !== 1 ? "s" : ""} needing review
            </span>
          </div>
          <div className="text-xs text-orange-600 mt-2 grid grid-cols-3 gap-2">
            {summary.poor.map(module => (
              <div key={module.group_name} className="flex items-center gap-1">
                <DefconBadge defcon={module.summary.group_defcon} size="sm" />
                <span>• {module.group_name}</span>
                <span className="font-medium">({(module.summary.score * 100).toFixed(1)}%)</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // Success Card - only show if no failures
  if (!hasFailures) {
    cards.push(
      <div
        key="success"
        className="p-4 rounded-lg border-l-4 bg-green-50"
        style={{ borderColor: getSeverityColorByLevel(4) }}
      >
        <div className="flex items-center gap-4 mb-3">
          <h2 className="text-lg font-semibold text-green-900">✅ All Systems Secure</h2>
          <DefconBadge defcon={summary.alertLevel} size="md" showLabel />
        </div>
        <div className="text-sm text-green-800">
          All {summary.totalModules} module{summary.totalModules !== 1 ? "s" : ""} performing
          acceptably
        </div>
        <div className="text-xs text-green-600 mt-1">
          No modules require immediate security attention
        </div>
      </div>
    );
  }

  // Performance Overview Card
  cards.push(
    <div
      key="performance"
      className="p-4 rounded-lg border-l-4 bg-gray-50"
      style={{ borderColor: getSeverityColorByLevel(3) }}
    >
      <div className="flex items-center gap-4 mb-3">
        <h2 className="text-lg font-semibold text-gray-900">📊 Performance Overview</h2>
        <DefconBadge defcon={3} size="md" showLabel />
      </div>
      <div className="space-y-1">
        <div className="text-sm text-gray-800 mb-2">Top 3 lowest scoring modules:</div>
        <div className="text-xs text-gray-600 space-y-0.5">
          {summary.worstModules.map((module, index) => (
            <div key={module.group_name} className="flex items-center gap-2">
              <span className="font-medium text-gray-500">{index + 1}.</span>
              <DefconBadge defcon={module.summary.group_defcon} size="sm" />
              <span>{module.group_name}</span>
              <span className="font-medium">({(module.summary.score * 100).toFixed(1)}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  return <>{cards}</>;
};

export default DefconSummaryPanel;
