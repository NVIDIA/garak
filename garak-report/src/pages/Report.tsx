/**
 * @file Report.tsx
 * @description Main report page component displaying Garak vulnerability scan results.
 *              Manages report data, filtering, sorting, and module visualization.
 * @module pages
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useEffect } from "react";
import { Flex, Spinner, Grid, StatusMessage } from "@kui/react";
import Footer from "../components/Footer";
import ReportHeader from "../components/Header";
import ReportDetails from "../components/ReportDetails";
import SummaryStatsCard from "../components/SummaryStatsCard";
import ReportFilterBar from "../components/ReportFilterBar";
import ModuleAccordion from "../components/ModuleAccordion";
import ErrorBoundary from "../components/ErrorBoundary";
import useFlattenedModules from "../hooks/useFlattenedModules";
import { useReportData } from "../hooks/useReportData";
import { useModuleFilters } from "../hooks/useModuleFilters";
import { useThemeMode } from "../hooks/useThemeMode";

/** Props for the Report page component */
interface ReportProps {
  /** Callback to change application theme */
  onThemeChange?: (theme: "light" | "dark" | "system") => void;
  /** Current theme setting */
  currentTheme?: "light" | "dark" | "system";
}

/**
 * Main report page displaying Garak vulnerability scan results.
 * Handles data loading, DEFCON filtering, sorting, and module accordion display.
 *
 * @param props - Component props
 * @param props.onThemeChange - Callback to change theme
 * @param props.currentTheme - Current theme setting
 * @returns Full report page with header, summary, modules, and footer
 */
function Report({ onThemeChange, currentTheme = "system" }: ReportProps) {
  // Load report data
  const { selectedReport, calibrationData, setupData } = useReportData();

  // Flatten modules from report
  const allModules = useFlattenedModules(selectedReport);

  // Filter and sort modules
  const { modules, selectedDefcons, sortBy, toggleDefcon, setSortBy } =
    useModuleFilters(allModules);

  // Theme mode
  const { isDark, toggleTheme } = useThemeMode(currentTheme, onThemeChange);

  // Update document title with target name
  useEffect(() => {
    const targetName =
      selectedReport?.meta?.target_name ||
      selectedReport?.meta?.model_name ||
      (setupData?.["plugins.model_name"] as string) ||
      null;

    document.title = targetName ? `NVIDIA Garak - ${targetName}` : "NVIDIA Garak";

    return () => {
      document.title = "NVIDIA Garak";
    };
  }, [selectedReport?.meta?.target_name, selectedReport?.meta?.model_name, setupData]);

  // Loading state
  if (!selectedReport) {
    return (
      <Flex style={{ height: "100vh", width: "100vw" }} align="center" justify="center">
        <Spinner size="medium" description="Loading reports..." />
      </Flex>
    );
  }

  return (
    <Flex direction="col" style={{ minHeight: "100vh" }}>
      <ReportHeader onThemeToggle={toggleTheme} isDark={isDark} />

      <Flex direction="col" style={{ flex: 1 }}>
        {/* Summary Section */}
        <Grid cols={{ base: 1, md: 2 }} gap="density-lg" padding="density-lg">
          <ErrorBoundary fallbackMessage="Failed to load report details. Please refresh the page.">
            <ReportDetails
              setupData={setupData}
              calibrationData={calibrationData}
              meta={selectedReport.meta}
            />
          </ErrorBoundary>
          <ErrorBoundary fallbackMessage="Failed to load summary statistics. Please refresh the page.">
            <SummaryStatsCard modules={allModules} />
          </ErrorBoundary>
        </Grid>

        {/* Filter Bar */}
        <ReportFilterBar
          selectedDefcons={selectedDefcons}
          onToggleDefcon={toggleDefcon}
          sortBy={sortBy}
          onSortChange={setSortBy}
        />

        {/* Module List */}
        {modules.length > 0 ? (
          <ErrorBoundary fallbackMessage="Failed to load modules. Please refresh the page.">
            <ModuleAccordion
              modules={modules}
              accordionKey={selectedReport?.meta.run_uuid ?? "default"}
              isDark={isDark}
            />
          </ErrorBoundary>
        ) : (
          <StatusMessage
            slotMedia={<i className="nv-icons-line-warning"></i>}
            slotHeading="No modules found in this report"
            slotSubheading="Try changing the filters or sorting options"
          />
        )}
      </Flex>

      <Footer />
    </Flex>
  );
}

export default Report;
