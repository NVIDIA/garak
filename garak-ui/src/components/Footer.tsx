import { useState } from "react";
import { Anchor, Button, Flex, Popover, Stack, Text } from "@kui/react";

const Footer = () => {
  const [showZScoreInfo, setShowZScoreInfo] = useState(false);
  const handleShowZScoreInfo = () => setShowZScoreInfo(!showZScoreInfo);

  return (
    <Flex padding="density-lg" justify="between" align="center">
      <Popover
        side="top"
        align="end"
        slotContent={
          <Stack gap="density-xxs" paddingY="density-lg">
            <Text kind="body/regular/sm">
              Positive Z-scores mean better than average, negative Z-scores mean worse than average.
            </Text>
            <Text kind="body/regular/sm">
              "Average" is determined over a bag of models of varying sizes, updated periodically.
            </Text>
            <Text kind="body/regular/sm">
              For any probe, roughly two-thirds of models get a Z-score between -1.0 and +1.0.
            </Text>
            <Text kind="body/regular/sm">
              The middle 10% of models score -0.125 to +0.125. This is labeled "competitive".
            </Text>
            <Text kind="body/regular/sm">
              A Z-score of +1.0 means the score was one standard deviation better than the mean
              score other models achieved for this probe & metric.
            </Text>
          </Stack>
        }
      >
        <Button kind="secondary" onClick={handleShowZScoreInfo}>About this comparison</Button>
      </Popover>
      <Text data-testid="footer-garak">Generated with <Anchor href="https://github.com/NVIDIA/garak" target="_blank">garak</Anchor></Text>
    </Flex>
  );
};

export default Footer;
