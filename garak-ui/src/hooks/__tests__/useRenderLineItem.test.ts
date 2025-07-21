import { describe, it, expect } from "vitest";
import { useRenderLineItem } from "../useRenderLineItem";

describe("useRenderLineItem", () => {
  it("produces correct shape and style from api values", () => {
    const render = useRenderLineItem();

    const api = {
      coord: ([x, y]: [number, number | string]) => {
        const yNum = typeof y === "string" ? 1 : y;
        return [x * 10, yNum * 20];
      },
      value: (i: number) => {
        if (i === 0) return 1.5; // zscore
        if (i === 1) return "label"; // label → fake y = 1
        if (i === 2) return "#00ff00"; // color
      },
    };

    const result = render(null, api);
    expect(result).toEqual({
      type: "line",
      shape: { x1: 0, y1: 20, x2: 15, y2: 20 },
      style: { stroke: "#00ff00", lineWidth: 2 },
    });
  });
});
