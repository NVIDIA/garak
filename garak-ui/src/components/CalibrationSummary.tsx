import { useState } from "react";
import type { CalibrationProps } from "../types/Calibration";

const CalibrationSummary = ({ calibration }: CalibrationProps) => {
  const [openSection, setOpenSection] = useState<string | null>(null);
  const toggle = (section: string) => setOpenSection(openSection === section ? null : section);

  return (
    <div className="space-y-4">
      {/* Calibration Summary */}
      <div className="border border-gray-200 rounded-md shadow-sm overflow-hidden">
        <button
          className="w-full text-left px-4 py-3 bg-gray-100 hover:bg-gray-200 font-semibold text-sm text-gray-800"
          onClick={() => toggle("summary")}
        >
          Calibration Summary
        </button>
        {openSection === "summary" && (
          <div className="px-4 py-3 space-y-1 text-sm text-gray-700 bg-white">
            <p className="flex gap-2">
              <strong className="whitespace-nowrap font-medium">Date:</strong>
              <span className="truncate max-w-full block font-normal">
                {new Date(calibration.calibration_date).toLocaleString()}
              </span>
            </p>
            <p className="flex gap-2">
              <strong className="whitespace-nowrap font-medium">Model Count:</strong>
              <span className="truncate max-w-full block font-normal">
                {calibration.model_count}
              </span>
            </p>
          </div>
        )}
      </div>

      {/*  Calibration Models */}
      <div className="border border-gray-200 rounded-md shadow-sm overflow-hidden">
        <button
          className="w-full text-left px-4 py-3 bg-gray-100 hover:bg-gray-200 font-semibold text-sm text-gray-800"
          onClick={() => toggle("models")}
        >
           Calibration Models
        </button>
        {openSection === "models" && (
          <ul className="px-4 py-3 text-sm text-gray-700 list-disc pl-5 space-y-1 bg-white">
            {calibration.model_list.split(", ").map((model: string, index: number) => (
              <li key={index} className="truncate">
                {model}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
};

export default CalibrationSummary;
