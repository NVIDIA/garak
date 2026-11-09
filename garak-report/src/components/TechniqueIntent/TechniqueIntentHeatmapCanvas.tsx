/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** ECharts owns every graphic; React owns selection, keyboard focus and previews. */
import { useMemo } from "react";
import ReactECharts from "echarts-for-react";
import type { ECharts, ECElementEvent } from "echarts";
import type { MatrixView } from "../../utils/techniqueIntentRollup";
import type { HeatmapSelection } from "../../types/TechniqueIntentHeatmap";
import type { HeatmapNavigation } from "../../hooks/useTechniqueIntentHeatmapNavigation";
import type { HeatmapKeyboard } from "../../hooks/useTechniqueIntentHeatmapKeyboard";
import type { useTechniqueIntentHeatmapOptions } from "../../hooks/useTechniqueIntentHeatmapOptions";
import { heatmapEventSelection } from "../../utils/techniqueIntentHeatmapSelection";
import { heatmapOutline } from "../../utils/techniqueIntentHeatmapGraphics";
import TechniqueIntentHeatmapAccessibility from "./TechniqueIntentHeatmapAccessibility";

interface Props {
  view: MatrixView;
  model: ReturnType<typeof useTechniqueIntentHeatmapOptions>;
  navigation: HeatmapNavigation;
  keyboard: HeatmapKeyboard;
  onSelect: (selection: HeatmapSelection) => void;
}
const clearHover = (_: unknown, chart: ECharts) =>
  chart.setOption({
    graphic: { elements: [{ id: "technique-intent-hover", ignore: true }] },
  });
const TechniqueIntentHeatmapCanvas = ({ view, model, navigation, keyboard, onSelect }: Props) => {
  const { layout, hoverColour } = model;
  const { setWindow } = navigation;
  const events = useMemo(
    () => ({
      click: (params: ECElementEvent) => {
        const next = heatmapEventSelection(params, view);
        if (next) onSelect(next);
      },
      datazoom: (_: unknown, chart: ECharts) => {
        const zoom = (
          chart.getOption().dataZoom as { startValue?: number; endValue?: number }[]
        )[0];
        const start = zoom.startValue ?? 0;
        setWindow({
          colStart: start,
          colSpan: (zoom.endValue ?? view.cols.length - 1) - start + 1,
        });
      },
      mouseover: (params: ECElementEvent, chart: ECharts) => {
        const target = heatmapEventSelection(params, view);
        if (!target || target.axis === "cell") return;
        const graphic = heatmapOutline(
          "technique-intent-hover",
          target,
          view,
          layout,
          "transparent"
        );
        chart.setOption({
          graphic: {
            elements: [{ ...graphic, z: 10, style: { fill: hoverColour } }],
          },
        });
      },
      mouseout: clearHover,
      globalout: clearHover,
    }),
    [view, layout, hoverColour, setWindow, onSelect]
  );
  return (
    <div
      ref={navigation.measure}
      role="grid"
      tabIndex={0}
      aria-label="Technique by intent pass rates"
      aria-rowcount={view.rows.length + 1}
      aria-colcount={view.cols.length + 1}
      aria-activedescendant={`${keyboard.id}-active`}
      aria-describedby={`${keyboard.id}-help`}
      onKeyDown={keyboard.onKeyDown}
      onFocus={keyboard.onFocus}
      onBlur={keyboard.onBlur}
      className="focus-visible:outline focus-visible:outline-2"
    >
      <div>
        <ReactECharts
          option={model.option}
          style={{ height: model.height, width: "100%" }}
          onEvents={events}
        />
      </div>
      <TechniqueIntentHeatmapAccessibility
        view={view}
        groups={model.groups}
        keyboard={keyboard}
        minEvaluations={model.minEvaluations}
      />
      {model.tooltipPortal}
    </div>
  );
};
export default TechniqueIntentHeatmapCanvas;
