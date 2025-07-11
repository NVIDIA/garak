import { useMemo, useState } from "react";
import type { SetupSectionProps } from "../types/SetupSection";
import { useValueFormatter } from "../hooks/useValueFormatter";

type GroupedSections = Record<string, Record<string, unknown>>;

const SetupSection = ({ setup }: SetupSectionProps) => {
  const { formatValue } = useValueFormatter();

  const groupedSections = useMemo(() => {
    if (!setup) return {};
    return Object.entries(setup).reduce<GroupedSections>((acc, [key, value]) => {
      const [category, field] = key.split(".");
      if (!category || !field) return acc;
      if (!acc[category]) acc[category] = {};
      acc[category][field] = value;
      return acc;
    }, {});
  }, [setup]);

  const sectionKeys = Object.keys(groupedSections);
  const [openSections, setOpenSections] = useState(
    Object.fromEntries(sectionKeys.map((key, i) => [key, i === 0]))
  );

  const [copiedField, setCopiedField] = useState<string | null>(null);

  const toggleSection = (key: string) => {
    setOpenSections(prev => ({ ...prev, [key]: !prev[key] }));
  };

  if (sectionKeys.length === 0) return null;

  return (
    <div className="space-y-2">
      {sectionKeys.map(section => {
        const isOpen = openSections[section];
        const fields = groupedSections[section];

        return (
          <div
            key={section}
            className="border border-gray-200 rounded-md shadow-sm overflow-hidden"
          >
            <button
              onClick={() => toggleSection(section)}
              className="w-full flex justify-between items-center px-4 py-2 bg-gray-100 hover:bg-gray-200 text-sm font-semibold"
            >
              <span className="capitalize">{section.replace(/_/g, " ")}</span>
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
                {isOpen ? (
                  <polyline points="18 15 12 9 6 15" />
                ) : (
                  <polyline points="6 9 12 15 18 9" />
                )}
              </svg>
            </button>

            {isOpen && (
              <div className="px-4 py-3 space-y-1 text-sm text-gray-800 bg-white">
                {Object.entries(fields).map(([key, val]) => {
                  const display = formatValue(val);
                  const showCopy = typeof display === "string" && display.length > 30;
                  const fieldId = `${section}.${key}`;

                  const handleCopy = async () => {
                    try {
                      await navigator.clipboard.writeText(display);
                      setCopiedField(fieldId);
                      setTimeout(() => setCopiedField(null), 2000);
                    } catch (err) {
                      console.warn("❌ Clipboard copy failed:", err);
                    }
                  };

                  return (
                    <p key={key} className="flex items-center gap-2">
                      <strong className="whitespace-nowrap">{key.replace(/_/g, " ")}:</strong>
                      <span
                        className="truncate flex-1 text-gray-800"
                        title={typeof display === "string" ? display : ""}
                      >
                        {display}
                      </span>
                      {showCopy && (
                        <button
                          onClick={handleCopy}
                          className="text-sm px-2 py-0.5 hover:bg-gray-100"
                          aria-label="copy to clipboard"
                          title="Copy to clipboard"
                        >
                          {copiedField === fieldId ? "✅" : "📋"}
                        </button>
                      )}
                    </p>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default SetupSection;
