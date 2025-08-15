export function useRenderLineItem() {
  return function renderLineItem(_params: any, api: any) {
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
