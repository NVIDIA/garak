import { useMemo } from "react";
import ReactECharts from "echarts-for-react";
import DetectorsView from "./DetectorsView";
import useSeverityColor from "../hooks/useSeverityColor";
import type { ProbesChartProps } from "../types/ProbesChart";
import type { ECElementEvent } from "echarts";
import { useProbeTooltip } from "../hooks/useProbeTooltip";
import InfoTooltip from "./InfoTooltip";
import ColorLegend from "./ColorLegend";

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

  const filtered = probesData;

  const getTooltip = useProbeTooltip(filtered);

  const option = useMemo(
    () => ({
      grid: { containLabel: true, bottom: 0, left: 75 },
      tooltip: {
        trigger: "item",
        formatter: getTooltip,
        confine: false,
        position: (pos: any, _params: any, dom: HTMLElement) => {
          const [x, y] = pos as [number, number];
          const margin = 10;
          const tipWidth = dom?.offsetWidth ?? 0;
          const vw = document.documentElement.clientWidth;

          const containerLeft = dom.parentElement?.getBoundingClientRect()?.left ?? 0;

          let clampedX = x;
          if (containerLeft + x + tipWidth + margin > vw) {
            clampedX = vw - tipWidth - margin - containerLeft;
          }
          if (containerLeft + clampedX < margin) {
            clampedX = margin - containerLeft;
          }

          return [clampedX, y];
        },
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
          barMaxWidth: 50,
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
                color: "#333",
              },
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
    <div className="space-y-2">
      {/* Header + controls */}
      <div className="flex flex-col gap-1">
        <div className="flex items-center gap-1">
          <h3 className="text-lg font-semibold">Probe scores</h3>
          <InfoTooltip>
            <p className="text-xs mb-2">
              A probe is a predefined set of prompts targeting a specific failure mode.
            </p>
            <p className="text-xs mb-2">
              Each bar shows the percentage of prompts where the model failed (higher = worse). Click a bar to drill down.
            </p>
            <ColorLegend />
          </InfoTooltip>
        </div>

      </div>

      {filtered.length === 0 ? (
        <p className="text-sm italic text-gray-500 py-8">No probes meet the current filter.</p>
      ) : (
        <div style={{ display: "flex" }}>
          <div style={{ flex: selectedProbe ? "20%" : "100%" }}>
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
                        label: (option.series[0] as any).data[0].label, // reuse label config
                        itemStyle: {
                          color: p.color,
                          opacity: isSelected ? 0.5 : 1,
                        },
                      };
                    }),
                  },
                ],
              }}
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
      )}
    </div>
  );
};

export default ProbesChart;
