import { useState } from "react";
import ReactECharts from "echarts-for-react";
import { useGroupedDetectors } from "../hooks/useGroupedDetectors";
import type { ChartDetector, Probe } from "../types/ProbesChart";
import { useTooltipFormatter } from "../hooks/useTooltipFormatter";
import { useDetectorsChartSeries } from "../hooks/useDetectorsChartSeries";
import useSeverityColor from "../hooks/useSeverityColor";
import DefconBadge from "./DefconBadge";
import { Stack, Tooltip, Text, Button, StatusMessage, Panel, Flex, Checkbox, Divider } from "@kui/react";


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
  const { getDefconColor } = useSeverityColor();

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
    <Panel 
      slotHeading={
        <>
          <Text kind="title/xs">Detector comparison</Text>
          <Tooltip slotContent={
            <Stack gap="density-xxs">
              <Text kind="body/regular/sm">Detectors score the model's response; higher Z-score = worse (relative to calibration).</Text>
              <Text kind="body/regular/sm">DEFCON levels indicate risk: DC-1 (Critical) to DC-5 (Minimal). Click DEFCON badges to filter.</Text>
            </Stack>
          }>
            <Button kind="tertiary">
              <i className="nv-icons-line-info-circle"></i>
            </Button>
          </Tooltip>
        </>
      }
      slotFooter={
        <Flex justify="end" gap="density-xs">
          <Checkbox 
            checked={hideUnavailable} 
            onCheckedChange={() => setHideUnavailable(!hideUnavailable)} 
            slotLabel="Hide N/A"
          />
        </Flex>
      }
    >
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
            confine: true,
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
            axisLabel: { 
              fontSize: 14,
              rich: {
                selected1: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(1) },
                selected2: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(2) },
                selected3: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(4) },
                selected4: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(4) },
                selected5: { fontWeight: 'bold', fontSize: 14, color: getDefconColor(5) },
              },
              formatter: (value: string, index: number) => {
                // Check if this label corresponds to the selected probe
                const isSelected = visible[index]?.probeName === probe.probe_name;
                // Use detector's defcon for color styling
                const detectorDefcon = visible[index]?.detector_defcon ?? 0;
                return isSelected ? `{selected${detectorDefcon}|${value}}` : value;
              }
            },
          },
          series: [lineSeries, pointSeries, naSeries],
        };

        const handleClick = (params: any) => {
          const clickedLabel = params.name;
          const match = allProbes.find(p => p.probe_name.includes(clickedLabel));
          if (match) setSelectedProbe(match);
        };

        return (
          <Stack key={detectorType} paddingBottom="density-3xl">
            <Stack>
              <Flex align="center" gap="density-xxs">
                <Text kind="mono/sm">{probe.probe_name}</Text>
                <Text kind="mono/sm">//</Text>
                <Text kind="title/sm">{detectorType}</Text>
                <Divider />
              </Flex>

              {/* Only show DEFCON filters if there are DEFCON values */}
              {[1, 2, 3, 4, 5].some(defcon => 
                (entries as any[]).filter(e => e.detector_defcon === defcon).length > 0
              ) && (
                <Flex gap="density-xs" align="center" paddingTop="density-md">
                  <Text kind="label/regular/md">DEFCON:</Text>
                  <Flex gap="density-xs" align="center">
                    {[1, 2, 3, 4, 5].map(defcon => {
                      const count = (entries as any[]).filter(e => e.detector_defcon === defcon).length;
                      if (count === 0) return null;
                      
                      const opacity = getDefconOpacity(detectorType, defcon);
                      
                      return (
                        <Flex
                          key={defcon}
                          gap="density-xs"
                          align="center"
                          onClick={() => toggleDefconForDetector(detectorType, defcon)}
                          style={{ opacity, cursor: "pointer" }}
                          title={`${count} entries at DEFCON ${defcon}. Click to ${opacity === 1 ? 'hide' : 'show'}.`}
                        >
                          <DefconBadge defcon={defcon} size="sm" />
                          <span className="text-xs text-gray-500">({count})</span>
                        </Flex>
                      );
                    })}
                  </Flex>
                </Flex>
              )}

              {visible.length === 0 ? (
                <Flex paddingTop="density-2xl">
                  <StatusMessage
                    size="small"
                    slotMedia={<i className="nv-icons-fill-warning"></i>}
                    slotHeading="No Data Available"
                    slotSubheading={(
                      <Stack gap="density-sm">
                        <Text kind="label/regular/md">All detector results for this comparison are unavailable (N/A).</Text>
                        <Text kind="label/regular/sm">Try unchecking "Hide N/A" to see unavailable entries, change DEFCON levels or select a different detector.</Text>
                      </Stack>
                    )}
                  />
                </Flex>
              ) : (
                <>
                  <ReactECharts
                    option={option}
                    style={{height: Math.max(200, 40 * visible.length + 80)}}
                    onEvents={{ click: handleClick }}
                  />
                </>
              )}
            </Stack>
          </Stack>
        );
      })}
    </Panel>
  );
};

export default DetectorsView;

