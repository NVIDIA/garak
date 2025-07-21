import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import ProbesChart from "../ProbesChart";
import { describe, it, expect, vi } from "vitest";

vi.mock("echarts-for-react", () => ({ __esModule:true, default: ()=> <div data-testid="chart"/> }));
vi.mock("../DetectorsView", () => ({ __esModule:true, default: () => <div/> }));
vi.mock("../../hooks/useSeverityColor", () => ({ default: () => ({ getSeverityColorByLevel: () => "#000", getSeverityLabelByLevel:()=>"" }) }));

const moduleData:any = {
  group_name:"m",
  summary:{group:"g",score:0,group_defcon:5,doc:"",group_link:"",group_aggregation_function:"avg",unrecognised_aggregation_function:false,show_top_group_score:false},
  probes:[
    {probe_name:"p1", summary:{probe_name:"p1",probe_score:0.2,probe_severity:5,probe_descr:"",probe_tier:1}, detectors:[]},
  ]
};

describe("ProbesChart slider", ()=>{
  it("shows placeholder when filter hides all", async ()=>{
    const setSel=vi.fn();
    render(<ProbesChart module={moduleData} selectedProbe={null} setSelectedProbe={setSel}/>);
    const slider= screen.getByRole("slider");
    fireEvent.change(slider,{ target:{ value:50}});
    expect(await screen.findByText(/No probes meet/)).toBeInTheDocument();
  });
}); 