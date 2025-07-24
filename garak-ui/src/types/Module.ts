import type { Probe } from "./ProbesChart";

export type ModuleData = {
  group_name: string;
  summary: {
    group: string;
    score: number;
    group_defcon: number;
    doc: string;
    group_link: string;
    group_aggregation_function: string;
    unrecognised_aggregation_function: boolean;
    show_top_group_score: boolean;
  };
  probes: Probe[];
};
