import { useMemo } from "react";
import ReactECharts from "echarts-for-react";
import DetectorsView from "./DetectorsView";
import useSeverityColor from "../hooks/useSeverityColor";
import type { ProbesChartProps } from "../types/ProbesChart";
import type { ECElementEvent } from "echarts";
import { useProbeTooltip } from "../hooks/useProbeTooltip";

const ProbesChart = ({ module, selectedProbe, setSelectedProbe }: ProbesChartProps) => {
  const { getSeverityColorByLevel, getSeverityLabelByLevel } = useSeverityColor();

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

  const getTooltip = useProbeTooltip(probesData);

  const option = useMemo(
    () => ({
      grid: { containLabel: true, bottom: 0, left: 75 },
      tooltip: {
        trigger: "item",
        formatter: getTooltip,
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
        },
      },
      yAxis: { type: "value" },
      series: [
        {
          type: "bar",
          barMinHeight: 5,
          data: probesData.map(p => {
            const isSelected = selectedProbe?.summary?.probe_name === p.summary?.probe_name;
            return {
              name: p.label,
              value: p.value,
              itemStyle: {
                color: p.color,
                opacity: isSelected ? 0.5 : 1,
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
    <div style={{ display: "flex" }}>
      <div style={{ flex: selectedProbe ? "20%" : "100%" }}>
        <ReactECharts
          option={option}
          style={{ height: 300, width: "100%" }}
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
        <div style={{ flex: "40%" }}>
          <DetectorsView
            probe={selectedProbe}
            allProbes={module.probes}
            setSelectedProbe={setSelectedProbe}
            data-testid="detectors-view"
          />
        </div>
      )}
    </div>
  );
};

export default ProbesChart;
