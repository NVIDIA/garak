import { useState } from "react";
import ReactECharts from "echarts-for-react";
import { useGroupedDetectors } from "../hooks/useGroupedDetectors";
import type { ChartDetector, Probe } from "../types/ProbesChart";
import { useTooltipFormatter } from "../hooks/useTooltipFormatter";
import { useSortedDetectors } from "../hooks/useSortedDetectors";
import { useDetectorsChartSeries } from "../hooks/useDetectorsChartSeries";
import useSeverityColor from "../hooks/useSeverityColor";
import InfoTooltip from "./InfoTooltip";

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
  const buildSeries = useDetectorsChartSeries();
  const formatTooltip = useTooltipFormatter();
  const { getSeverityColorByLevel } = useSeverityColor();
  const probeColor = getSeverityColorByLevel(probe.summary?.probe_severity ?? 0);

  return (
    <div className="flex flex-col gap-8 pl-4 border-l border-gray-300">
      <div className="mb-4 flex flex-col gap-1">
        <div className="flex items-center gap-1">
          <h3 className="text-lg font-semibold">Detector comparison</h3>
          <InfoTooltip>
            Detectors score the model’s response; higher Z-score = worse (relative to calibration).
          </InfoTooltip>
        </div>
        <p className="text-sm text-gray-600">
          Showing detectors for:
          <span className="ml-1 px-2 py-0.5 rounded-full text-white" style={{ background: probeColor }}>
            {probe.probe_name}
          </span>
        </p>
      </div>
      {[...Object.entries(groupedDetectors)].sort(([a],[b])=>a.localeCompare(b)).map(([detectorType, entries]) => {
        const sortedEntries = sortDetectors(entries) as unknown as ChartDetector[];
        const { pointSeries, lineSeries, naSeries, visible } = buildSeries(
          sortedEntries,
          hideUnavailable
        );

        const yAxisLabels = visible.map(d => {
          if (d.attempt_count != null && d.hit_count != null) {
            return `${d.label} (${d.attempt_count}/${d.hit_count})`;
          }
          return d.label;
        });

        const option = {
          grid: { containLabel: true, left: 10, right: 10, top: 10, bottom: 10 },
          tooltip: {
            trigger: "item",
            formatter: (params: any) => formatTooltip({ data: params.data, detectorType }),
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
