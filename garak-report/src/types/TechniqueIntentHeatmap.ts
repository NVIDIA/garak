/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { ECElementEvent } from "echarts";

/** A tested cell, an entire technique, or an entire intent. */
export type HeatmapSelection =
  | { axis: "cell"; technique: string; intent: string }
  | { axis: "technique" | "intent"; key: string };
export interface HeatmapCell {
  value: [number, number, number];
  rowKey: string;
  colKey: string;
}
export interface HeatmapWindow {
  colStart?: number;
  colSpan?: number;
}
export interface HeatmapCursor {
  row: number;
  col: number;
}
export type HeatmapEvent = Partial<ECElementEvent>;
export type TooltipCallback = (ticket: string, content: string | HTMLElement) => void;
export type TooltipFormatter = (
  params: { value?: unknown; data?: HeatmapCell },
  ticket: string,
  callback: TooltipCallback
) => HTMLElement | string;
