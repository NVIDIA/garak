import { useState } from "react";
import SetupSection from "./SetupSection";
import CalibrationSummary from "./CalibrationSummary";
import type { ReportDetailsProps } from "../types/ReportEntry";

const ReportDetails = ({ setupData, calibrationData }: ReportDetailsProps) => {
  const [showDetails, setShowDetails] = useState(false);
  const toggleDetails = () => setShowDetails(!showDetails);

  return (
    <>
      <div className="p-4">
        <div
          data-testid="report-summary"
          className="w-full border rounded-lg p-4 bg-white shadow cursor-pointer"
          onClick={toggleDetails}
        >
          <div className="space-y-2">
            <h1 className="text-2xl font-bold">Report for {setupData?.["transient.run_id"]}</h1>
            <div className="space-y-1 text-sm text-gray-700">
              <p>
                <strong>Garak Version:</strong> {setupData?.["_config.version"]}
              </p>
              <p>
                <strong>Model Type:</strong> {setupData?.["plugins.model_type"]}
              </p>
              <p>
                <strong>Model Name:</strong> {setupData?.["plugins.model_name"] || "N/A"}
              </p>
              <p>
                <strong>Run ID:</strong> {setupData?.["transient.run_id"]}
              </p>
              <p>
                <strong>Start Time:</strong>{" "}
                {new Date(setupData?.["transient.starttime_iso"]).toLocaleString()}
              </p>
            </div>
          </div>
        </div>
      </div>

      {showDetails && (
        <>
          {/* Backdrop */}
          <div
            data-testid="report-backdrop"
            onClick={toggleDetails}
            className="fixed inset-0 bg-black/10 backdrop-blur-sm z-40"
            role="presentation"
          />

          {/* Sidebar */}
          <div
            data-testid="report-sidebar"
            className="fixed top-0 right-0 w-full sm:w-[820px] h-full bg-white border-l border-gray-200 shadow-lg z-50 overflow-y-auto"
            style={{ transition: "transform 0.3s ease-in-out" }}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b">
              <h2 className="text-lg font-semibold">Report Details</h2>
              <button
                className="text-gray-500 hover:text-black text-xl"
                onClick={toggleDetails}
                aria-label="Close"
              >
                ×
              </button>
            </div>

            <div className="p-4 space-y-6">
              <div data-testid="setup-section">
                <h3 className="text-md font-semibold mb-2">Setup Section</h3>
                <SetupSection setup={setupData} />
              </div>

              {calibrationData && (
                <div data-testid="calibration-summary">
                  <h3 className="text-md font-semibold mb-2">Calibration Details</h3>
                  <CalibrationSummary calibration={calibrationData} />
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </>
  );
};

export default ReportDetails;
