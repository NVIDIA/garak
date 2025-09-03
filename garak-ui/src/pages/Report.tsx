import { useEffect, useState, useMemo } from "react";
import useFlattenedModules from "../hooks/useFlattenedModules";
import Footer from "../components/Footer";
import ReportHeader from "../components/Header";
import ReportDetails from "../components/ReportDetails";
import SummaryStatsCard from "../components/SummaryStatsCard";
import type { ReportEntry } from "../types/ReportEntry";
import { Accordion, Anchor, Badge, Flex, Spinner, Stack, StatusMessage, Text, Group, Checkbox } from "@kui/react";
import useSeverityColor from "../hooks/useSeverityColor";
import ProbesChart from "../components/ProbesChart";
import DefconBadge from "../components/DefconBadge";
import type { Probe } from "../types/ProbesChart";

declare global {
  interface Window {
    reportsData?: ReportEntry[];
  }
}

// prettier-ignore
// @ts-expect-error: __GARAK_INSERT_HERE__ replaced at build time for production
const BUILD_REPORTS: ReportEntry[] = typeof __GARAK_INSERT_HERE__ !== "undefined" ? __GARAK_INSERT_HERE__ : [];

function Report() {
  const [selectedReport, setSelectedReport] = useState<ReportEntry | null>(null);
  const [calibrationData, setCalibrationData] = useState<any | null>(null);
  const [setupData, setSetupData] = useState<Record<string, unknown> | null>(null);
  const { getDefconBadgeColor } = useSeverityColor();

  const allModules = useFlattenedModules(selectedReport);

  const [selectedProbe, setSelectedProbe] = useState<Probe | null>(null);
  const [selectedDefcons, setSelectedDefcons] = useState<number[]>([1, 2, 3, 4, 5]);
  const [sortBy, setSortBy] = useState<"defcon" | "alphabetical">("defcon");

  // Apply filtering and sorting
  const modules = useMemo(() => {
    let filtered = allModules.filter(module => 
      selectedDefcons.includes(module.summary.group_defcon)
    );

    if (sortBy === "defcon") {
      filtered = filtered.sort((a, b) => a.summary.group_defcon - b.summary.group_defcon);
    } else {
      filtered = filtered.sort((a, b) => a.group_name.localeCompare(b.group_name));
    }

    return filtered;
  }, [allModules, selectedDefcons, sortBy]);

  const toggleDefcon = (defcon: number) => {
    setSelectedDefcons(prev => 
      prev.includes(defcon) 
        ? prev.filter(d => d !== defcon)
        : [...prev, defcon].sort()
    );
  };

  useEffect(() => {
    if (Array.isArray(BUILD_REPORTS) && BUILD_REPORTS.length > 0) {
      setSelectedReport(BUILD_REPORTS[0]);
    } else if (window.reportsData && Array.isArray(window.reportsData)) {
      console.warn("Using reportsData from window (dev mode).");
      setSelectedReport(window.reportsData[0]);
    } else {
      console.error("❌ No reports data found in build or dev fallback.");
    }
  }, []);

  useEffect(() => {
    setCalibrationData(selectedReport?.meta.calibration || null);
    setSetupData(selectedReport?.meta.setup || null);
  }, [selectedReport]);

  if (!selectedReport) return (
    <Flex 
      style={{ height: "100vh", width: "100vw" }}
      align="center"
      justify="center"
    >
      <Spinner size="medium" description="Loading reports..." />
    </Flex>
  );

  return (
    <>
      <ReportHeader />
      <Flex gap="density-md" padding="density-md" align="center">
        <ReportDetails setupData={setupData} calibrationData={calibrationData} />
        <SummaryStatsCard modules={allModules} />
      </Flex>

      <Flex gap="density-2xl" paddingY="density-xl" paddingX="density-md" align="center" justify="between">
        <Flex gap="density-sm" align="center">
          <Text kind="label/bold/md">Filter by DEFCON:</Text>
          <Group kind="gap">
            {[1, 2, 3, 4, 5].map(defcon => {
              const isSelected = selectedDefcons.includes(defcon);
              return (
                <button
                  key={defcon}
                  onClick={() => toggleDefcon(defcon)}
                  style={{ opacity: isSelected ? 1 : 0.3, cursor: "pointer" }}
                  title={`DEFCON ${defcon}. Click to ${isSelected ? 'hide' : 'show'}.`}
                >
                  <DefconBadge defcon={defcon} size="sm" />
                </button>
              );
            })}
          </Group>
        </Flex>

        <Flex gap="density-sm" align="center">
          <Text kind="label/bold/md">Sort by:</Text>
          <Flex gap="density-xs" align="center">
            <Checkbox
              checked={sortBy === "defcon"}
              onCheckedChange={() => setSortBy("defcon")}
              slotLabel="DEFCON"
            />
            <Checkbox
              checked={sortBy === "alphabetical"}
              onCheckedChange={() => setSortBy("alphabetical")}
              slotLabel="Alphabetical"
            />
          </Flex>
        </Flex>
      </Flex>

      {modules.length ? (
        <Accordion
          items={
            modules.map((module) => ({
              slotTrigger: (
                <Flex 
                  direction="row" 
                  gap="density-lg" 
                >
                  <Flex direction="col" gap="density-sm">
                    <Badge 
                      color={getDefconBadgeColor(module.summary.group_defcon)} 
                      kind="solid" 
                      className="w-[70px]"
                    >
                      <Text kind="label/bold/xl">
                        {(module.summary.score * 100).toFixed(0)}%
                      </Text>
                    </Badge>
                    <Badge 
                      color={getDefconBadgeColor(module.summary.group_defcon)} 
                      kind="outline" 
                      className="w-[70px]"
                    >
                      <Text kind="label/bold/md">
                        DC-{module.summary.group_defcon}
                      </Text>
                    </Badge>
                  </Flex>
                  <Stack align="start" gap="density-md">
                    <Text kind="label/bold/2xl">{module.group_name}</Text>
                    <Anchor href={module.summary.group_link} target="_blank" rel="noopener noreferrer">
                      <Text dangerouslySetInnerHTML={{ __html: module.summary.doc }} />
                    </Anchor>
                  </Stack>
                  {/* <Badge color="gray" kind="solid">{module.probes.length} tests</Badge> */}
                </Flex>
              ),
              slotContent: (
                <ProbesChart
                  module={{ ...module, probes: module.probes ?? [] }}
                  setSelectedProbe={setSelectedProbe}
                  selectedProbe={selectedProbe}
                />
              ),
              value: module.group_name
            }))
          }
          kind="single"
          onValueChange={() => setSelectedProbe(null)}
        />
      ) : (
        <StatusMessage 
          slotMedia={<i className="nv-icons-line-warning"></i>}
          slotHeading="No modules found in this report"
          slotSubheading="Try changing the filters or sorting options"
        />
      )}
      <Footer />
    </>
  );
}

export default Report;
