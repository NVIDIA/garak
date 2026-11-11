/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Render KUI previews through the existing React root, without a server renderer. */
import { useCallback, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import TechniqueIntentTooltip from "../components/TechniqueIntent/TechniqueIntentTooltip";
import TechniqueIntentAxisTooltip from "../components/TechniqueIntent/TechniqueIntentAxisTooltip";
import type { MatrixView } from "../utils/techniqueIntentRollup";
import { sameHeatmapSelection } from "../utils/techniqueIntentHeatmapSelection";
import type {
  HeatmapSelection,
  TooltipCallback,
  TooltipFormatter,
} from "../types/TechniqueIntentHeatmap";
import type { HeatmapGroups } from "./useTechniqueIntentHeatmapData";

interface Request {
  target: HeatmapSelection;
  ticket: string;
  callback: TooltipCallback;
  view: MatrixView;
}
export function useTechniqueIntentHeatmapTooltip(
  view: MatrixView,
  groups: HeatmapGroups,
  minEvaluations: number
) {
  const [host] = useState(() => document.createElement("div"));
  const [request, setRequest] = useState<Request | null>(null);
  const committed = useRef<Request | null>(null);
  const show = useCallback(
    (target: HeatmapSelection, ticket: string, callback: TooltipCallback) => {
      // Reuse committed content while letting the latest pending hover win.
      setRequest(previous =>
        previous?.view === view &&
        sameHeatmapSelection(previous.target, target) &&
        (previous === committed.current || previous.ticket === ticket)
          ? previous
          : { target, ticket, callback, view }
      );
      return host;
    },
    [view, host]
  );
  useLayoutEffect(() => {
    if (!request || request.view !== view) return;
    committed.current = request;
    request.callback(request.ticket, host);
  }, [request, view, host]);
  const formatters = useMemo(
    () => ({
      cell: (({ data }, ticket, callback) =>
        data
          ? show({ axis: "cell", technique: data.rowKey, intent: data.colKey }, ticket, callback)
          : "") as TooltipFormatter,
      technique: (({ value }, ticket, callback) =>
        groups.technique.has(String(value))
          ? show({ axis: "technique", key: String(value) }, ticket, callback)
          : "") as TooltipFormatter,
      intent: (({ value }, ticket, callback) =>
        groups.intent.has(String(value))
          ? show({ axis: "intent", key: String(value) }, ticket, callback)
          : "") as TooltipFormatter,
    }),
    [groups, show]
  );
  let content = null;
  if (request?.view === view) {
    const target = request.target;
    if (target.axis === "cell")
      content = (
        <TechniqueIntentTooltip
          view={view}
          technique={target.technique}
          intent={target.intent}
          minEvaluations={minEvaluations}
        />
      );
    else {
      const group = groups[target.axis].get(target.key);
      if (group)
        content = (
          <TechniqueIntentAxisTooltip
            group={group}
            axis={target.axis}
            total={target.axis === "technique" ? view.cols.length : view.rows.length}
          />
        );
    }
  }
  return { formatters, portal: createPortal(content, host) };
}
