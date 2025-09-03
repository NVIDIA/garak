import "@testing-library/jest-dom";
import { render, screen } from "@testing-library/react";
import ProbesChart from "../ProbesChart";
import { describe, it, expect, vi } from "vitest";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Button: ({ children, onClick, ...props }: any) => <button onClick={onClick} {...props}>{children}</button>,
  Flex: ({ children, ...props }: any) => <div data-testid="flex" {...props}>{children}</div>,
  Grid: ({ children, ...props }: any) => <div data-testid="grid" {...props}>{children}</div>,
  Stack: ({ children, ...props }: any) => <div data-testid="stack" {...props}>{children}</div>,
  Text: ({ children, kind, ...props }: any) => <span data-kind={kind} {...props}>{children}</span>,
  Tooltip: ({ children, slotContent, ...props }: any) => (
    <div data-testid="tooltip" {...props}>
      {children}
      {slotContent && <div data-testid="tooltip-content">{slotContent}</div>}
    </div>
  ),
}));

vi.mock("echarts-for-react", () => ({ __esModule:true, default: ()=> <div data-testid="chart"/> }));
vi.mock("../DetectorsView", () => ({ __esModule:true, default: () => <div/> }));
vi.mock("../../hooks/useSeverityColor", () => ({ default: () => ({ getSeverityColorByLevel: () => "#000", getSeverityLabelByLevel:()=>"", getDefconColor: () => "#ff0000" }) }));

const moduleData:any = {
  group_name:"m",
  summary:{group:"g",score:0,group_defcon:5,doc:"",group_link:"",group_aggregation_function:"avg",unrecognised_aggregation_function:false,show_top_group_score:false},
  probes:[
    {probe_name:"p1", summary:{probe_name:"p1",probe_score:0.2,probe_severity:5,probe_descr:"",probe_tier:1}, detectors:[]},
  ]
};

describe("ProbesChart slider", ()=>{
  it("renders without slider after removal", ()=>{
    const setSel=vi.fn();
    render(<ProbesChart module={moduleData} selectedProbe={null} setSelectedProbe={setSel}/>);
    expect(screen.queryByRole("slider")).toBeNull();
  });
}); 