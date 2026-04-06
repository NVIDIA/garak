/**
 * @file ProgressBar.tsx
 * @description Stacked progress bar showing pass/fail ratio.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Props for ProgressBar component */
interface ProgressBarProps {
  /** Pass percentage (0-100), from backend absolute_score */
  passPercent: number;
  /** Whether there are actual failures (to determine if red portion shows) */
  hasFailures: boolean;
  /** Height of the bar in pixels */
  height?: number;
}

/**
 * Stacked progress bar visualizing pass/fail ratio.
 * Green portion = passed, Red portion = failed (only if hasFailures).
 *
 * @param props - Component props
 * @returns Stacked progress bar element
 */
const ProgressBar = ({ passPercent, hasFailures, height = 8 }: ProgressBarProps) => {
  const failPercent = 100 - passPercent;

  return (
    <div
      style={{
        flex: 1,
        minWidth: "200px",
        height: `${height}px`,
        borderRadius: "4px",
        overflow: "hidden",
        backgroundColor: "var(--color-tk-200)",
        display: "flex",
      }}
    >
      {/* Green (passed) portion */}
      {passPercent > 0 && (
        <div
          style={{
            width: `${passPercent}%`,
            height: "100%",
            backgroundColor: "var(--color-green-500)",
          }}
        />
      )}
      {/* Red (failed) portion - only show if there are actual failures */}
      {hasFailures && failPercent > 0 && (
        <div
          style={{
            width: `${failPercent}%`,
            height: "100%",
            backgroundColor: "var(--color-red-700)",
          }}
        />
      )}
    </div>
  );
};

export default ProgressBar;
