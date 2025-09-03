import { useMemo } from "react";
import ReactECharts from "echarts-for-react";
import DetectorsView from "./DetectorsView";
import useSeverityColor from "../hooks/useSeverityColor";
import type { ProbesChartProps } from "../types/ProbesChart";
import type { ECElementEvent } from "echarts";
import { useProbeTooltip } from "../hooks/useProbeTooltip";
import { Button, Flex, Grid, Stack, Text, Tooltip } from "@kui/react";
import ColorLegend from "./ColorLegend";

const ProbesChart = ({ module, selectedProbe, setSelectedProbe }: ProbesChartProps) => {
  const { getSeverityColorByLevel, getSeverityLabelByLevel, getDefconColor } = useSeverityColor();

  const probesData = useMemo(() => {
    return module.probes.map(probe => {
      const score = probe.summary?.probe_score ?? 0;
      const name = probe.summary?.probe_name ?? probe.probe_name;
      const severity = probe.summary?.probe_severity;

      return {
        ...probe,
        label: name,
        value: score * 100,
        color: getSeverityColorByLevel(severity),
        severity,
        severityLabel: getSeverityLabelByLevel(severity),
      };
    });
  }, [module, getSeverityColorByLevel, getSeverityLabelByLevel]);

  const filtered = probesData;

  const getTooltip = useProbeTooltip(filtered);

  const option = useMemo(
    () => ({
      grid: { 
        containLabel: true, 
        bottom: 0, 
        left: 10, 
        right: 20 
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
        axisLabel: {
          rotate: 45,
          interval: 0,
          fontSize: 14,
          rich: {
            selected1: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(1) },
            selected2: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(2) },
            selected3: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(3) },
            selected4: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(4) },
            selected5: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(5) },
          },
          formatter: (value: string, index: number) => {
            const probe = probesData[index];
            const isSelected = selectedProbe?.summary?.probe_name === probe.summary?.probe_name;
            const defcon = probe.severity ?? 0;
            return isSelected ? `{selected${defcon}|${value}}` : value;
          }
        },
      },
      yAxis: { type: "value" },
      series: [
        {
          type: "bar",
          barMinHeight: 5,
          barMaxWidth: 80,
          data: probesData.map(p => {
            const isSelected = selectedProbe?.summary?.probe_name === p.summary?.probe_name;
            return {
              name: p.label,
              value: p.value,
              label: {
                show: true,
                position: "top",
                formatter: ({ value }: { value: number }) => `${value.toFixed(0)}%`,
                fontSize: 12,
                fontWeight: isSelected ? 'bold' : 'normal',
                color: isSelected ? getDefconColor(p.severity ?? 0) : "#333",
              },
              itemStyle: {
                color: p.color,
                opacity: selectedProbe ? (isSelected ? 1 : 0.3) : 1,
              },
            };
          }),
          barCategoryGap: "30%",
        },
      ],
    }),
    [probesData, selectedProbe?.summary?.probe_name, getTooltip]
  );

  return (
    <>
      {filtered.length === 0 ? (
        <p className="text-sm italic text-gray-500 py-8">No probes meet the current filter.</p>
      ) : (
        <Grid cols={selectedProbe ? 2 : 1}>
          <div>
            <Flex align="center" gap="density-xxs">
              <Text kind="title/xs">Probe scores</Text>
              <Tooltip slotContent={
                <Stack gap="density-xxs">
                  <Text kind="body/regular/sm">A probe is a predefined set of prompts targeting a specific failure mode.</Text>
                  <Text kind="body/regular/sm">Each bar shows the percentage of prompts where the model failed (higher = worse). Click a bar to drill down.</Text>
                  <ColorLegend />
                </Stack>
              }>
                <Button kind="tertiary">
                  <i className="nv-icons-line-info-circle"></i>
                </Button>
              </Tooltip>
            </Flex>
          
            <ReactECharts
              option={{
                ...option,
                xAxis: {
                  ...option.xAxis,
                  data: filtered.map(p => {
                    const [, ...rest] = p.label.split(".");
                    return rest.join(".");
                  }),
                },
                series: [
                  {
                    ...option.series[0],
                    data: filtered.map(p => {
                      const isSelected = selectedProbe?.summary?.probe_name === p.summary?.probe_name;
                      return {
                        name: p.label,
                        value: p.value,
                        label: {
                          show: true,
                          position: "top",
                          formatter: ({ value }: { value: number }) => `${value.toFixed(0)}%`,
                          fontSize: 12,
                          fontWeight: isSelected ? 'bold' : 'normal',
                          color: isSelected ? getDefconColor(p.severity ?? 0) : "#333",
                        },
                        itemStyle: {
                          color: p.color,
                          opacity: selectedProbe ? (isSelected ? 1 : 0.3) : 1,
                        },
                      };
                    }),
                  },
                ],
              }}
              onEvents={{
                click: (params: ECElementEvent) => {
                  const clicked = module.probes.find(p => p.summary?.probe_name === params.name);
                  if (clicked) {
                    setSelectedProbe(
                      selectedProbe?.summary?.probe_name === clicked.summary?.probe_name
                        ? null
                        : clicked
                    );
                  }
                },
              }}
            />
          </div>
          {selectedProbe && (
            <DetectorsView
              probe={selectedProbe}
              allProbes={module.probes}
              setSelectedProbe={setSelectedProbe}
              data-testid="detectors-view"
            />
          )}
        </Grid>
      )}
    </>
  );
};

export default ProbesChart;
