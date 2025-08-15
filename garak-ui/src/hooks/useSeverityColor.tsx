import { useCallback } from "react";
import theme from "../styles/theme";

const useSeverityColor = () => {
  const getSeverityColorByLevel = useCallback((severity: number): string => {
    switch (severity) {
      case 5:
        return theme.colors.b400; // Minimal - Light Blue
      case 4:
        return theme.colors.g400; // Low - Light Green
      case 3:
        return theme.colors.y300; // Moderate - Yellow
      case 2:
        return theme.colors.r400; // High - Light Red
      case 1:
        return theme.colors.r600; // Critical - Dark Red
      default:
        return theme.colors.tk150; // Default Grey
    }
  }, []);

  const getSeverityColorByComment = useCallback((comment: string | null | undefined): string => {
    const commentLower = comment?.toLowerCase() || "";
    if (commentLower.includes("very poor")) return theme.colors.r700;
    if (commentLower.includes("poor")) return theme.colors.r400;
    if (commentLower.includes("below average")) return theme.colors.y400;
    if (commentLower.includes("above average")) return theme.colors.g700;
    if (commentLower.includes("average")) return theme.colors.g400;
    if (commentLower.includes("excellent")) return theme.colors.g700;
    if (commentLower.includes("competitive")) return theme.colors.g400;
    return theme.colors.tk150;
  }, []);

  const getDefconColor = useCallback((defcon: number | null | undefined): string => {
    switch (defcon) {
      case 1:
        return theme.colors.r700;
      case 2:
        return theme.colors.r400;
      case 3:
        return theme.colors.y300;
      case 4:
        return theme.colors.g400;
      case 5:
        return theme.colors.g700;
      default:
        return theme.colors.tk150;
    }
  }, []);

  const getSeverityLabelByLevel = useCallback((defcon: number | null | undefined): string => {
    switch (defcon) {
      case 1:
        return "Very Bad";
      case 2:
        return "Below Average";
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

  return {
    getSeverityColorByLevel,
    getSeverityColorByComment,
    getDefconColor,
    getSeverityLabelByLevel,
  };
};

export default useSeverityColor;
