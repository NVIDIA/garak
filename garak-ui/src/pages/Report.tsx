import { useEffect, useState } from "react";
import Module from "../components/Module";
import Footer from "../components/Footer";
import ReportHeader from "../components/Header";
import ReportDetails from "../components/ReportDetails";
import type { ReportEntry } from "../types/ReportEntry";

// @ts-expect-error: this is replaced at build time
const REPORTS_DATA: ReportEntry[] = __GARAK_INSERT_HERE__;

function Report() {
  const [selectedReport, setSelectedReport] = useState<ReportEntry | null>(null);
  const [calibrationData, setCalibrationData] = useState<any | null>(null);
  const [setupData, setSetupData] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    if (Array.isArray(REPORTS_DATA) && REPORTS_DATA.length > 0) {
      const firstReport = REPORTS_DATA[0];
      setSelectedReport(firstReport);
    } else {
      console.error("❌ No report data embedded at build time.");
    }
  }, []);

  useEffect(() => {
    setCalibrationData(selectedReport?.meta.calibration);
    setSetupData(selectedReport?.meta.setup || null);
  }, [selectedReport]);

  if (!selectedReport) return <p>Loading report...</p>;

  return (
    <div className="flex flex-col justify-between min-h-screen">
      <div className="flex flex-col">
        <ReportHeader />

        <ReportDetails setupData={setupData} calibrationData={calibrationData} />

        {selectedReport.results && selectedReport.results.length > 0 ? (
          <div className="flex flex-col">
            {selectedReport.results.map((module, index) => (
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
