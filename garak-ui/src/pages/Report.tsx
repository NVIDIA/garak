import { useEffect, useState } from "react";
import useFlattenedModules from "../hooks/useFlattenedModules";
import Module from "../components/Module";
import Footer from "../components/Footer";
import ReportHeader from "../components/Header";
import ReportDetails from "../components/ReportDetails";
import type { ReportEntry } from "../types/ReportEntry";

declare global {
  interface Window {
    reportsData?: ReportEntry[];
  }
}

// prettier-ignore
// @ts-expect-error: __GARAK_INSERT_HERE__ replaced at build time for production
const BUILD_REPORTS: ReportEntry[] = typeof __GARAK_INSERT_HERE__ !== "undefined" ? __GARAK_INSERT_HERE__ : [];

function Report() {
  const [selectedReport, setSelectedReport] = useState<ReportEntry | null>(null);
  const [calibrationData, setCalibrationData] = useState<any | null>(null);
  const [setupData, setSetupData] = useState<Record<string, unknown> | null>(null);

  const modules = useFlattenedModules(selectedReport) ?? selectedReport?.results ?? [];

  useEffect(() => {
    if (Array.isArray(BUILD_REPORTS) && BUILD_REPORTS.length > 0) {
      setSelectedReport(BUILD_REPORTS[0]);
    } else if (window.reportsData && Array.isArray(window.reportsData)) {
      console.warn("Using reportsData from window (dev mode).");
      setSelectedReport(window.reportsData[0]);
    } else {
      console.error("❌ No reports data found in build or dev fallback.");
    }
  }, []);

  useEffect(() => {
    setCalibrationData(selectedReport?.meta.calibration || null);
    setSetupData(selectedReport?.meta.setup || null);
  }, [selectedReport]);

  if (!selectedReport) return <p>Loading report...</p>;

  return (
    <div className="flex flex-col justify-between min-h-screen">
      <div className="flex flex-col">
        <ReportHeader />
        <ReportDetails setupData={setupData} calibrationData={calibrationData} />
        {modules.length ? (
          <div className="flex flex-col">
            {modules.map((module, index) => (
              <Module key={index} module={module} />
            ))}
          </div>
        ) : (
          <div className="flex items-center justify-center p-6">
            <p className="text-gray-500">No modules found in this report.</p>
          </div>
        )}
      </div>
      <Footer calibration={calibrationData} />
    </div>
  );
}

export default Report;
