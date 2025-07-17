import type { ReportEntry } from "./ReportEntry";

export type HeaderProps = {
  reports: ReportEntry[];
  selectedReport: ReportEntry | null;
  setSelectedReport: (r: ReportEntry | null) => void;
};
