import { useState } from "react";
import useSeverityColor from "../hooks/useSeverityColor";
import ProbesChart from "./ProbesChart";
import type { ModuleData } from "../types/Module";
import type { Probe } from "../types/ProbesChart";

const Module = ({ module }: { module: ModuleData }) => {
  const { getSeverityColorByLevel } = useSeverityColor();
  const [isOpen, setIsOpen] = useState(false);
  const [selectedProbe, setSelectedProbe] = useState<Probe | null>(null);

  const handleSetIsOpen = () => setIsOpen(!isOpen);
  const color = getSeverityColorByLevel(module.summary.group_defcon);

  const totalProbes = module.probes.length;

  return (
    <div className="p-4 border-b cursor-pointer" style={{ borderColor: color }}>
      <div className="flex justify-between items-center" onClick={handleSetIsOpen}>
        <div className="flex items-center gap-4">
          <div
            className="px-3 py-1 rounded-sm text-white font-semibold w-16 text-center"
            style={{ background: color }}
          >
            <span className="text-lg">{(module.summary.score * 100).toFixed(0)}%</span>
          </div>

          <div className="flex flex-col">
            <h2 className="text-xl font-bold flex items-center gap-2">
              {module.group_name}
              <span
                className="text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-700"
                title="Number of probe classes in this group"
              >
                {totalProbes} tests
              </span>
            </h2>
            <a
              href={module.summary.group_link}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 hover:underline"
              onClick={e => e.stopPropagation()}
            >
              <span dangerouslySetInnerHTML={{ __html: module.summary.doc }} />
            </a>
          </div>
        </div>

        <div className="text-xl">
          {isOpen ? (
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <polyline points="18 15 12 9 6 15" /> {/* Upward arrow */}
            </svg>
          ) : (
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <polyline points="6 9 12 15 18 9" /> {/* Downward arrow */}
            </svg>
          )}
        </div>
      </div>

      {isOpen && (
        <ProbesChart
          module={{ ...module, probes: module.probes ?? [] }}
          setSelectedProbe={setSelectedProbe}
          selectedProbe={selectedProbe}
        />
      )}
    </div>
  );
};

export default Module;
