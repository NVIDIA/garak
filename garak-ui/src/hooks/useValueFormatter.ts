export const useValueFormatter = () => {
  const formatValue = (value: unknown): string => {
    if (Array.isArray(value)) return value.join(", ");
    if (typeof value === "boolean") return value ? "Enabled" : "Disabled";
    if (value == null) return "N/A";
    return String(value);
  };

  return { formatValue };
};
