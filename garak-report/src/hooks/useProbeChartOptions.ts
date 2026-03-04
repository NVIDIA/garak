/**
 * @file useProbeChartOptions.ts
 * @description Hook to build ECharts options for probe bar chart.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import type { Probe, EnrichedProbeData } from "../types/ProbesChart";
import useSeverityColor from "./useSeverityColor";
import { useProbeTooltip } from "./useProbeTooltip";
import { THEME_COLORS, CHART_DIMENSIONS, CHART_LABEL_CONFIG, CHART_OPACITY } from "../constants";
import { formatPercentage } from "../utils/formatPercentage";

// Re-export for backward compatibility
export type { EnrichedProbeData } from "../types/ProbesChart";

/**
 * Builds ECharts options for probe bar chart visualization.
 *
 * @param probesData - Enriched probe data array
 * @param selectedProbe - Currently selected probe or null
 * @param isDark - Whether dark theme is active
 * @returns ECharts option configuration object
 */
/** 
 * Module color palette - hex values from KUI theme
 * These must be hex values (not CSS variables) for ECharts to render them
 */
const MODULE_COLORS = [
  "#0074df", // blue-500
  "#3f8500", // green-500
  "#a846db", // purple-500
  "#0d8473", // teal-500
  "#d73d00", // yellow-500
  "#e52020", // red-500
];

export function useProbeChartOptions(
  probesData: EnrichedProbeData[],
  selectedProbe: Probe | null,
  isDark?: boolean,
  allModuleNames?: string[]
) {
  const { getDefconColor } = useSeverityColor();
  const textColor = isDark ? THEME_COLORS.text.dark : THEME_COLORS.text.light;
  const getTooltip = useProbeTooltip(probesData);

  // Build color map from stable allModuleNames list (or fall back to probesData)
  const moduleColorMap = useMemo(() => {
    const moduleList = allModuleNames ?? (() => {
      const modules = new Set<string>();
      probesData.forEach(p => {
        const moduleName = p.label.split(".")[0];
        if (moduleName) modules.add(moduleName);
      });
      return Array.from(modules).sort();
    })();
    
    const map = new Map<string, string>();
    moduleList.forEach((m, i) => {
      map.set(m, MODULE_COLORS[i % MODULE_COLORS.length]);
    });
    return map;
  }, [allModuleNames, probesData]);

  return useMemo(
    () => ({
      grid: {
        containLabel: CHART_DIMENSIONS.grid.containLabel,
        bottom: CHART_DIMENSIONS.grid.bottom,
        left: CHART_DIMENSIONS.grid.left,
        right: CHART_DIMENSIONS.grid.right,
      },
      tooltip: {
        trigger: "item",
        formatter: getTooltip,
        confine: true,
      },
      xAxis: {
        type: "category",
        data: probesData.map(p => {
          const [, ...rest] = p.label.split(".");
          return rest.join(".");
        }),
        triggerEvent: true,
        axisLabel: {
          rotate: CHART_DIMENSIONS.axis.labelRotation,
          interval: 0,
          fontSize: CHART_DIMENSIONS.axis.fontSize,
          color: textColor,
          rich: {
            selected1: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(1),
            },
            selected2: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(2),
            },
            selected3: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(3),
            },
            selected4: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(4),
            },
            selected5: {
              fontWeight: "bold",
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: getDefconColor(5),
            },
            dimmed: {
              fontSize: CHART_DIMENSIONS.axis.fontSize,
              color: textColor,
              opacity: CHART_OPACITY.dimmed,
            },
            // Module dot styles - created dynamically based on module colors
            ...Object.fromEntries(
              Array.from(moduleColorMap.entries()).map(([moduleName, color]) => [
                `dot_${moduleName}`,
                {
                  backgroundColor: color,
                  width: 8,
                  height: 8,
                  borderRadius: 4,
                },
              ])
            ),
          },
          formatter: (value: string, index: number) => {
            const probe = probesData[index];
            const isSelected = selectedProbe?.summary?.probe_name === probe.summary?.probe_name;
            const defcon = probe.severity ?? 0;
            
            // Only show module dot if there are multiple modules
            const showDot = moduleColorMap.size > 1;
            const moduleName = probe.label.split(".")[0];
            const dot = showDot ? `{dot_${moduleName}| } ` : "";

            if (selectedProbe && !isSelected) {
              return `${dot}{dimmed|${value}}`;
            }

            return isSelected ? `${dot}{selected${defcon}|${value}}` : `${dot}${value}`;
          },
        },
        axisLine: { lineStyle: { color: textColor } },
      },
      yAxis: {
        type: "value",
        min: 0,
        max: 100,
        axisLabel: { color: textColor },
        axisLine: { lineStyle: { color: textColor } },
        splitLine: {
          lineStyle: {
            color: isDark ? THEME_COLORS.chart.splitLine.dark : THEME_COLORS.chart.splitLine.light,
          },
        },
      },
      series: [
        {
          type: "bar",
          barMinHeight: CHART_DIMENSIONS.bar.minHeight,
          barMaxWidth: CHART_DIMENSIONS.bar.maxWidth,
          data: probesData.map(p => {
            const isSelected = selectedProbe?.summary?.probe_name === p.summary?.probe_name;
            return {
              name: p.label,
              value: p.value,
              label: {
                show: CHART_LABEL_CONFIG.show,
                position: CHART_LABEL_CONFIG.position,
                formatter: ({ value }: { value: number }) => formatPercentage(value),
                fontSize: CHART_LABEL_CONFIG.fontSize,
                fontWeight: isSelected ? "bold" : "normal",
                color: isSelected ? getDefconColor(p.severity ?? 0) : textColor,
              },
              itemStyle: {
                color: p.color,
                opacity: selectedProbe
                  ? isSelected
                    ? CHART_OPACITY.full
                    : CHART_OPACITY.dimmed
                  : CHART_OPACITY.full,
              },
            };
          }),
          barCategoryGap: CHART_DIMENSIONS.bar.categoryGap,
        },
      ],
    }),
    [probesData, selectedProbe, getTooltip, getDefconColor, isDark, textColor, moduleColorMap]
  );
}

