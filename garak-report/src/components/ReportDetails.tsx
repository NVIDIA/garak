/**
 * @file ReportDetails.tsx
 * @description Report summary panel with expandable side panel for detailed information.
 *              Shows target info, version, and provides access to metadata/calibration.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useState } from "react";
import SetupSection from "./SetupSection";
import CalibrationSummary from "./CalibrationSummary";
import MetadataSection from "./MetadataSection";
import type { ReportDetailsProps } from "../types/ReportEntry";
import { Badge, Flex, Panel, SidePanel, Text, Accordion, Stack } from "@kui/react";

/**
 * Report summary card with expandable detail side panel.
 * Displays target information and provides access to metadata, setup, and calibration.
 *
 * @param props - Component props
 * @param props.setupData - Garak configuration data
 * @param props.calibrationData - Calibration metadata
 * @param props.meta - Report metadata
 * @returns Clickable summary panel with detail side panel
 */
const ReportDetails = ({ setupData, calibrationData, meta }: ReportDetailsProps) => {
  const [showDetails, setShowDetails] = useState(false);
  const toggleDetails = () => setShowDetails(!showDetails);

  const targetType = meta.target_type || meta.model_type || setupData?.["plugins.model_type"] || "";
  const targetName = meta.target_name || meta.model_name || setupData?.["plugins.model_name"] || "";

  // Helper to clean up module prefixes (e.g., "test.Repeat" -> "Repeat")
  // Only strips known module prefixes, preserves version numbers like "qwen2.5"
  const cleanName = (name: string) => {
    if (!name) return name;
    // Only strip if it starts with a known module prefix pattern
    const knownPrefixes = ["test.", "huggingface.", "nim.", "rest.", "litellm."];
    for (const prefix of knownPrefixes) {
      if (name.startsWith(prefix)) {
        return name.substring(prefix.length);
      }
    }
    return name;
  };

  const cleanTargetType = cleanName(targetType);
  const cleanTargetName = cleanName(targetName);

  // Build the heading: target_type:target_name, or just one, or fall back to run ID
  // Only add separator if both exist
  const heading =
    cleanTargetType && cleanTargetName
      ? `${cleanTargetType}:${cleanTargetName}`
      : cleanTargetType || cleanTargetName || setupData?.["transient.run_id"] || "Unknown";

  return (
    <>
      <Panel
        data-testid="report-summary"
        elevation="mid"
        onClick={toggleDetails}
        style={{ cursor: "pointer" }}
        slotHeading={
          <Stack gap="density-xxs">
            <Text kind="label/bold/md">Report for</Text>
            <Text kind="title/lg">{heading}</Text>
          </Stack>
        }
      >
        <Flex gap="density-md" wrap="wrap">
          <Badge color="green" kind="outline">
            Garak Version: {setupData?.["_config.version"]}
          </Badge>

          <Badge color="green" kind="outline">
            Start Time: {new Date(setupData?.["transient.starttime_iso"]).toLocaleString()}
          </Badge>

          {/* Show warning if aggregation unknown */}
          {meta.aggregation_unknown && (
            <Badge color="yellow" kind="solid">
              Aggregation Method Unknown
            </Badge>
          )}
        </Flex>
      </Panel>

      <SidePanel
        modal
        slotHeading="Report Details"
        data-testid="report-sidebar"
        open={showDetails}
        onInteractOutside={toggleDetails}
        hideCloseButton
        density="compact"
        style={{ width: "520px" }}
      >
        <Accordion
          kind="single"
          items={[
            {
              slotTrigger: <Text kind="title/xs">Report Metadata</Text>,
              slotContent: <MetadataSection meta={meta} />,
              value: "metadata",
            },
            {
              slotTrigger: <Text kind="title/xs">Setup Section</Text>,
              slotContent: <SetupSection setup={setupData} />,
              value: "setup",
            },
            {
              slotTrigger: <Text kind="title/xs">Calibration Details</Text>,
              slotContent: calibrationData && <CalibrationSummary calibration={calibrationData} />,
              value: "calibration",
            },
          ]}
        />
      </SidePanel>
    </>
  );
};

export default ReportDetails;
