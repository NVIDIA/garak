import useSeverityColor from "../hooks/useSeverityColor";
import { Flex, Text, Button } from "@kui/react";

const levels = [1, 2, 3, 4, 5];

const ColorLegend = ({ onClose }: { onClose?: () => void }) => {
  const { getSeverityColorByLevel, getSeverityLabelByLevel } = useSeverityColor();

  return (
    <Flex gap="density-xl">
      {levels.map(l => (
        <Flex key={l} align="center" gap="density-xs">
          <div
            style={{ 
              background: getSeverityColorByLevel(l), 
              width: 14, 
              height: 14, 
              borderRadius: 2,
              flexShrink: 0
            }}
            aria-label={getSeverityLabelByLevel(l)}
          />
          <Text kind="body/regular/sm">{getSeverityLabelByLevel(l)}</Text>
        </Flex>
      ))}
      {onClose && (
        <Flex justify="end">
          <Button
            kind="tertiary"
            size="small"
            onClick={onClose}
            aria-label="Hide legend"
          >
            ×
          </Button>
        </Flex>
      )}
    </Flex>
  );
};

export default ColorLegend; 