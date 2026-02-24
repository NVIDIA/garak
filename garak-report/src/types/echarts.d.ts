/**
 * @file echarts.d.ts
 * @description Type declarations for echarts-for-react and custom ECharts types.
 *              Covers the specific ECharts APIs used in this project.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

declare module "echarts-for-react" {
  import { CSSProperties } from "react";

  export interface EChartsOption {
    [key: string]: unknown;
  }

  export interface ReactEChartsProps {
    option: EChartsOption;
    style?: CSSProperties;
    className?: string;
    theme?: string | object;
    onEvents?: Record<string, (params: unknown) => void>;
    notMerge?: boolean;
    lazyUpdate?: boolean;
    opts?: {
      renderer?: "canvas" | "svg";
      width?: number | string;
      height?: number | string;
    };
  }

  export default class ReactECharts extends React.Component<ReactEChartsProps> {}
}

/** Parameters passed to ECharts tooltip formatters and event handlers */
export interface EChartsTooltipParams {
  name: string;
  value: number | number[];
  data?: unknown;
  seriesName?: string;
  componentType?: string;
  [key: string]: unknown;
}

/** Data structure for detector chart data points */
export interface EChartsDetectorData {
  probeName?: string;
  label?: string;
  zscore?: number | null;
  detector_score?: number;
  detector_defcon?: number;
  comment?: string;
  attempt_count?: number;
  hit_count?: number;
  fail_count?: number;
  passed?: number;
  failed?: number;
  total?: number;
  unavailable?: boolean;
  itemStyle?: {
    color?: string;
  };
}

/** API object passed to custom series renderItem functions */
export interface EChartsRenderItemAPI {
  value(dim: number): number;
  coord(data: number[]): number[];
  size(dataSize: number[]): number[];
  style(opt?: Record<string, unknown>): Record<string, unknown>;
  styleEmphasis(opt?: Record<string, unknown>): Record<string, unknown>;
  visual(visualType: string): unknown;
  barLayout(opt: { count: number }): { offsetCenter: number; width: number }[];
  currentSeriesIndices(): number[];
  font(opt: { fontSize?: number; fontWeight?: string; fontFamily?: string }): string;
}
