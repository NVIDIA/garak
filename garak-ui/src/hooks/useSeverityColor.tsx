import { useCallback } from "react";
import { getColor } from "@kui/foundations";

const useSeverityColor = () => {
  const getSeverityColorByLevel = useCallback((severity: number): string => {
    switch (severity) {
      case 5:
        return getColor("--teal-200"); // Excellent - Blue  
      case 4:
        return getColor("--green-200"); // Good - Green
      case 3:
        return getColor("--green-200"); // Average - Yellow
      case 2:
        return getColor("--yellow-200"); // Poor - Red
      case 1:
        return getColor("--red-200"); // Critical - Dark Red
      default:
        return getColor("--gray-200"); // Default Grey
    }
  }, []);

  const getSeverityColorByComment = useCallback((comment: string | null | undefined): string => {
    const commentLower = comment?.toLowerCase() || "";
    if (commentLower.includes("very poor")) return getColor("--red-200");
    if (commentLower.includes("poor")) return getColor("--red-200");
    if (commentLower.includes("below average")) return getColor("--yellow-200");
    if (commentLower.includes("average")) return getColor("--green-200");
    if (commentLower.includes("above average")) return getColor("--green-200");
    if (commentLower.includes("excellent")) return getColor("--teal-200");
    if (commentLower.includes("competitive")) return getColor("--teal-200");
    return getColor("--gray-200");
  }, []);

  const getDefconColor = useCallback((defcon: number | null | undefined): string => {
    switch (defcon) {
      case 1:
        return getColor("--red-700"); // Critical - Dark Red
      case 2:
        return getColor("--red-400"); // Poor - Red
      case 3:
        return getColor("--yellow-200"); // Average - Yellow
      case 4:
        return getColor("--green-400"); // Good - Green
      case 5:
        return getColor("--teal-400"); // Excellent - Blue
      default:
        return getColor("--green-400");
    }
  }, []);

  const getSeverityLabelByLevel = useCallback((defcon: number | null | undefined): string => {
    switch (defcon) {
      case 1:
        return "Critical";
      case 2:
        return "Poor";
      case 3:
        return "Average";
      case 4:
        return "Good";
      case 5:
        return "Excellent";
      default:
        return "Unknown";
    }
  }, []);

  const getDefconBadgeColor = useCallback((level: number): "blue" | "gray" | "green" | "purple" | "red" | "teal" | "yellow" => {
    switch (level) {
      case 1: return "red";     // Critical
      case 2: return "yellow";  // Poor
      case 3: return "green";    // Moderate
      case 4: return "green";   // Good
      case 5: return "teal";    // Excellent
      default: return "gray";
    }
  }, []);

  return {
    getSeverityColorByLevel,
    getSeverityColorByComment,
    getDefconColor,
    getSeverityLabelByLevel,
    getDefconBadgeColor
  };
};

export default useSeverityColor;
