/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Numeric pass-rate scale and a distinct marker for untested intersections. */
import { Flex, Text } from "@kui/react";
import { CSS_COLOR_VARS, DEFCON_LEVELS } from "../../constants";

const gradient = `linear-gradient(to right, ${DEFCON_LEVELS.map(
  level => `var(${CSS_COLOR_VARS.riskRamp[level]})`
).join(", ")})`;

const TechniqueIntentHeatmapLegend = ({ minEvaluations }: { minEvaluations: number }) => (
  <Flex align="center" gap="density-lg" wrap="wrap" role="group" aria-label="Pass rate legend">
    <Flex align="center" gap="density-xs">
      <Text kind="label/regular/sm">Pass rate</Text>
      <Text kind="label/regular/sm">0%</Text>
      <span
        aria-hidden="true"
        style={{ width: 160, height: 8, borderRadius: 2, background: gradient }}
      />
      <Text kind="label/regular/sm">100%</Text>
    </Flex>
    <Text kind="label/regular/sm" style={{ color: "var(--text-color-secondary)" }}>
      Lower means more failures
    </Text>
    {minEvaluations > 0 && (
      <Flex align="center" gap="density-xs">
        <span
          aria-hidden="true"
          style={{
            width: 12,
            height: 12,
            border: "1px solid var(--border-color-base)",
            background:
              "repeating-linear-gradient(135deg, transparent 0 4px, var(--text-color-secondary) 4px 5px)",
          }}
        />
        <Text kind="label/regular/sm">
          Fewer than {minEvaluations.toLocaleString()} evaluations
        </Text>
      </Flex>
    )}
    <Flex align="center" gap="density-xs">
      <span
        aria-hidden="true"
        style={{ width: 12, height: 12, border: "1px solid var(--border-color-base)" }}
      />
      <Text kind="label/regular/sm">Not evaluated</Text>
    </Flex>
  </Flex>
);

export default TechniqueIntentHeatmapLegend;
