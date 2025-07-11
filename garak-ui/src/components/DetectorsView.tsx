import { useState } from "react";
import ReactECharts from "echarts-for-react";
import { useGroupedDetectors } from "../hooks/useGroupedDetectors";
import type { ChartDetector, Probe } from "../types/ProbesChart";
import { useTooltipFormatter } from "../hooks/useTooltipFormatter";
import { useSortedDetectors } from "../hooks/useSortedDetectors";
import { useDetectorsChartSeries } from "../hooks/useDetectorsChartSeries";

const DetectorsView = ({
  probe,
  allProbes,
  setSelectedProbe,
}: {
  probe: Probe;
  allProbes: Probe[];
  setSelectedProbe: (p: Probe) => void;
}) => {
  const [hideUnavailable, setHideUnavailable] = useState(true);
  const groupedDetectors = useGroupedDetectors(probe, allProbes);
  const sortDetectors = useSortedDetectors();
  const buildSeries = useDetectorsChartSeries(); // ✅ valid hook call
  const formatTooltip = useTooltipFormatter();   // ✅ valid hook call

  return (
    <div className="flex flex-col gap-8 pl-4 border-l border-gray-300">
      {Object.entries(groupedDetectors).map(([detectorType, entries]) => {
        const sortedEntries = sortDetectors(entries) as unknown as ChartDetector[];
        const { pointSeries, lineSeries, naSeries, visible } = buildSeries(
          sortedEntries,
          hideUnavailable
        );

        const yAxisLabels = visible.map(d => d.label);

        const option = {
          grid: { containLabel: true, left: 10, right: 10, top: 10, bottom: 10 },
          tooltip: {
            trigger: "item",
            formatter: (params: any) => formatTooltip({ data: params.data, detectorType }),
          },
          xAxis: {
            type: "value",
            name: "Z-Score",
            nameLocation: "middle",
            nameGap: 30,
            min: -3,
            max: 3,
          },
          yAxis: {
            type: "category",
            data: yAxisLabels,
            axisLabel: { fontSize: 14 },
          },
          series: [lineSeries, pointSeries, naSeries],
        };

        const handleClick = (params: any) => {
          const clickedLabel = params.name;
          const match = allProbes.find(p => p.probe_name.includes(clickedLabel));
          if (match) setSelectedProbe(match);
        };

        return (
          <div key={detectorType}>
            <div className="flex justify-between items-center w-full mb-2">
              <h3 className="text-lg font-semibold">{detectorType}</h3>
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="checkbox"
                  checked={hideUnavailable}
                  onChange={() => setHideUnavailable(!hideUnavailable)}
                  className="accent-gray-600"
                />
                Hide N/A
              </label>
            </div>

            {visible.length === 0 && hideUnavailable ? (
              <div className="text-sm text-gray-500 italic">All entries are unavailable (N/A).</div>
            ) : (
              <ReactECharts
                option={option}
                style={{
                  height: 40 * sortedEntries.length + 60,
                  background: "white",
                }}
                onEvents={{ click: handleClick }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
};

export default DetectorsView;
