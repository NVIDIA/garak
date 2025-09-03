import { useState } from "react";
import SetupSection from "./SetupSection";
import CalibrationSummary from "./CalibrationSummary";
import type { ReportDetailsProps } from "../types/ReportEntry";
import { Badge, Flex, PageHeader, SidePanel, Text, Accordion, Button } from "@kui/react";

const ReportDetails = ({ setupData, calibrationData }: ReportDetailsProps) => {
  const [showDetails, setShowDetails] = useState(false);
  const toggleDetails = () => setShowDetails(!showDetails);

  return (
    <>
      <PageHeader
        data-testid="report-summary"
        kind="floating"
        slotSubheading={<Text kind="label/bold/xl">Report for</Text>}
        slotHeading={<Text onClick={toggleDetails} kind="title/xl">{setupData?.["transient.run_id"]}</Text>}
        slotActions={
          <Button kind="secondary" onClick={toggleDetails}>More info</Button>
        }
      >
        <Flex gap="density-md" wrap="wrap">
          <Badge color="green" kind="outline">Garak Version: {setupData?.["_config.version"]}</Badge>
          <Badge color="green" kind="outline">Model Type: {setupData?.["plugins.model_type"]}</Badge>
          {setupData?.["plugins.model_name"] && (
            <Badge color="green" kind="outline">Model Name: {setupData?.["plugins.model_name"]}</Badge>
          )}
          <Badge color="green" kind="outline">Start Time: {new Date(setupData?.["transient.starttime_iso"]).toLocaleString()}</Badge>
        </Flex>
      </PageHeader>

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
              slotTrigger: <Text kind="title/xs">Setup Section</Text>,
              slotContent: <SetupSection setup={setupData} />,
              value: "setup",
            },
            {
              slotTrigger: <Text kind="title/xs">Calibration Details</Text>,
              slotContent: calibrationData && <CalibrationSummary calibration={calibrationData} />,
              value: "calibration",
            }
          ]}
        />
      </SidePanel>
    </>
  );
};

export default ReportDetails;
