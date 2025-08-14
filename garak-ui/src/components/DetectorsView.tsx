import { useState } from "react";
import ReactECharts from "echarts-for-react";
import { useGroupedDetectors } from "../hooks/useGroupedDetectors";
import type { ChartDetector, Probe } from "../types/ProbesChart";
import { useTooltipFormatter } from "../hooks/useTooltipFormatter";
import { useDetectorsChartSeries } from "../hooks/useDetectorsChartSeries";
import useSeverityColor from "../hooks/useSeverityColor";
import InfoTooltip from "./InfoTooltip";
import DefconBadge from "./DefconBadge";

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
  const [selectedDefconByDetector, setSelectedDefconByDetector] = useState<Record<string, number[]>>({});
  const groupedDetectors = useGroupedDetectors(probe, allProbes);
  const buildSeries = useDetectorsChartSeries();
  const formatTooltip = useTooltipFormatter();
  const { getSeverityColorByLevel } = useSeverityColor();
  const probeColor = getSeverityColorByLevel(probe.summary?.probe_severity ?? 0);

  const toggleDefconForDetector = (detectorType: string, defcon: number) => {
    setSelectedDefconByDetector(prev => {
      const currentSelected = prev[detectorType] || [1, 2, 3, 4, 5];
      const newSelected = currentSelected.includes(defcon)
        ? currentSelected.filter(d => d !== defcon)
        : [...currentSelected, defcon].sort();
      
      return {
        ...prev,
        [detectorType]: newSelected,
      };
    });
  };

  const getDefconOpacity = (detectorType: string, defcon: number): number => {
    const selected = selectedDefconByDetector[detectorType] || [1, 2, 3, 4, 5];
    return selected.includes(defcon) ? 1 : 0.3;
  };

  return (
    <div className="flex flex-col gap-8 pl-4 border-l border-gray-300">
      <div className="mb-4 flex flex-col gap-1">
        <div className="flex items-center gap-1">
          <h3 className="text-lg font-semibold">Detector comparison</h3>
          <InfoTooltip>
            Detectors score the model's response; higher Z-score = worse (relative to calibration).
            DEFCON levels indicate risk: DC-1 (Critical) to DC-5 (Minimal). Click DEFCON badges to filter.
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
        // Filter by DEFCON and availability  
        const chartEntries = entries as ChartDetector[];
        const selectedDefcons = selectedDefconByDetector[detectorType] || [1, 2, 3, 4, 5];
        const filteredEntries = chartEntries.filter((entry: ChartDetector) => {
          if (hideUnavailable && entry.unavailable) return false;
          if (entry.detector_defcon && !selectedDefcons.includes(entry.detector_defcon)) return false;
          return true;
        });
        
        // Convert to format expected by sortDetectors - using zscore for sorting
        const sortableEntries = filteredEntries.map(entry => ({
          ...entry,
          zscore: entry.zscore ?? 0,
        }));
        
        const sortedEntries = sortableEntries.sort((a, b) => {
          if (a.zscore == null) return 1;
          if (b.zscore == null) return -1;
          return a.zscore - b.zscore;
        });
        
        const { pointSeries, lineSeries, naSeries, visible } = buildSeries(
          sortedEntries,
          hideUnavailable
        );

        const yAxisLabels = visible.map(d => {
          let label = d.label;
          if (d.attempt_count != null && d.hit_count != null) {
            label = `${d.label} (${d.attempt_count}/${d.hit_count})`;
          }
          return label;
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
              <div className="flex items-center gap-2">
                <h3 className="text-lg font-semibold">{detectorType}</h3>
                {/* Clickable DEFCON distribution for this detector type */}
                <div className="flex items-center gap-1">
                  {[1, 2, 3, 4, 5].map(defcon => {
                    const count = (entries as any[]).filter(e => e.detector_defcon === defcon).length;
                    if (count === 0) return null;
                    
                    const opacity = getDefconOpacity(detectorType, defcon);
                    
                    return (
                      <button
                        key={defcon}
                        onClick={() => toggleDefconForDetector(detectorType, defcon)}
                        className="flex items-center gap-1 hover:bg-gray-50 px-1 py-0.5 rounded transition-all"
                        style={{ opacity }}
                        title={`${count} entries at DEFCON ${defcon}. Click to ${opacity === 1 ? 'hide' : 'show'}.`}
                      >
                        <DefconBadge defcon={defcon} size="sm" />
                        <span className="text-xs text-gray-500">({count})</span>
                      </button>
                    );
                  })}
                </div>
              </div>
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

            {visible.length === 0 ? (
              <div className="text-sm text-gray-500 italic">
                {hideUnavailable ? "All entries are unavailable (N/A)." : "No entries match the current DEFCON filter."}
              </div>
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
