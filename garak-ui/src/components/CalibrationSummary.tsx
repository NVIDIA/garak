import type { CalibrationProps } from "../types/Calibration";
import { Tabs, Text, Stack, Flex } from "@kui/react";

const CalibrationSummary = ({ calibration }: CalibrationProps) => {
  return (
    <Tabs
      items={[
        {
          value: "summary",
          children: "Calibration Summary",
          slotContent: (
            <Stack gap="density-xl">
              <Flex gap="density-xs" align="center">
                <Text kind="label/bold/sm" className="whitespace-nowrap">
                  Date:
                </Text>
                <Text kind="body/regular/sm" className="flex-1">
                  {new Date(calibration.calibration_date).toLocaleString()}
                </Text>
              </Flex>
              <Flex gap="density-xs" align="center">
                <Text kind="label/bold/sm" className="whitespace-nowrap">
                  Model Count:
                </Text>
                <Text kind="body/regular/sm" className="flex-1">
                  {calibration.model_count}
                </Text>
              </Flex>
            </Stack>
          )
        },
        {
          value: "models",
          children: "Calibration Models",
          slotContent: (
            <Stack gap="density-xs">
              <Text kind="label/bold/sm">
                Models:
              </Text>
              <Stack gap="density-xs">
                {calibration.model_list.split(", ").map((model: string, index: number) => (
                  <Flex key={index} align="center">
                    <i className="nv-icons-line-chevron-right"></i>
                    <Text kind="body/regular/sm">{model}</Text>
                  </Flex>
                ))}
              </Stack>
            </Stack>
          )
        }
      ]}
    />
  );
};

export default CalibrationSummary;
