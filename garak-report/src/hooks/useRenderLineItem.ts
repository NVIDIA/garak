/**
 * @file useRenderLineItem.ts
 * @description Hook providing custom render function for ECharts lollipop chart lines.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { EChartsRenderItemAPI } from "../types/echarts.d";

/**
 * Provides a custom renderItem function for ECharts lollipop chart lines.
 * Draws horizontal lines from x=0 to the data point's x position.
 *
 * @returns Render function for ECharts custom series
 */
export function useRenderLineItem() {
  return function renderLineItem(_params: unknown, api: EChartsRenderItemAPI) {
    const y = api.coord([0, api.value(1)])[1];
    const x0 = api.coord([0, api.value(1)])[0];
    const x1 = api.coord([api.value(0), api.value(1)])[0];

    return {
      type: "line",
      shape: { x1: x0, y1: y, x2: x1, y2: y },
      style: { stroke: api.value(2), lineWidth: 2 },
    };
  };
}
