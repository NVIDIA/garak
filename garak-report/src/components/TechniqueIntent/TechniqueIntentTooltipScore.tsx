/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Shared pass-rate and risk presentation for pairing and axis previews. */
import { Badge, Flex, Stack, Text } from "@kui/react";
import { DEFCON_BADGE_COLORS, DEFCON_LABELS, scoreToDefcon } from "../../constants";
import { formatRate } from "../../utils/formatPercentage";
const TechniqueIntentTooltipScore = ({
  score,
  label = "Pass rate",
}: {
  score: number;
  label?: string;
}) => {
  const level = scoreToDefcon(score);
  return (
    <Flex align="center" justify="between" gap="density-md">
      <Stack gap="density-xxs">
        <Text kind="title/md">{formatRate(score)}</Text>
        <Text kind="label/regular/sm">{label}</Text>
      </Stack>
      <Stack gap="density-xs" align="end">
        <Badge color={DEFCON_BADGE_COLORS[level]} kind="solid">
          DC-{level}
        </Badge>
        <Text kind="label/regular/sm">{DEFCON_LABELS[level]}</Text>
      </Stack>
    </Flex>
  );
};
export default TechniqueIntentTooltipScore;
