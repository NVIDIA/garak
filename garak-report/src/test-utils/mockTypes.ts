/**
 * @file mockTypes.ts
 * @description Type-safe mock components and utilities for tests.
 *              Provides proper types for mocked @kui/react components.
 * @module test-utils
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import type { ReactNode, CSSProperties, MouseEventHandler } from "react";

// ============================================================================
// Base Types
// ============================================================================

/** Base props for all mock components */
export interface MockComponentProps {
  children?: ReactNode;
  className?: string;
  style?: CSSProperties;
  "data-testid"?: string;
}

// ============================================================================
// Layout Components
// ============================================================================

/** Props for Flex mock component */
export interface MockFlexProps extends MockComponentProps {
  direction?: string;
  gap?: string;
  align?: string;
  justify?: string;
  wrap?: string;
  paddingTop?: string;
  paddingBottom?: string;
  paddingX?: string;
  paddingY?: string;
  padding?: string;
}

/** Props for Stack mock component */
export interface MockStackProps extends MockComponentProps {
  gap?: string;
  align?: string;
  paddingTop?: string;
  paddingBottom?: string;
}

/** Props for Grid mock component */
export interface MockGridProps extends MockComponentProps {
  cols?: number | Record<string, number>;
  gap?: string;
  padding?: string;
}

/** Props for Group mock component */
export interface MockGroupProps extends MockComponentProps {
  kind?: string;
}

// ============================================================================
// Text and Typography
// ============================================================================

/** Props for Text mock component */
export interface MockTextProps extends MockComponentProps {
  kind?: string;
  title?: string;
  onClick?: MouseEventHandler;
  dangerouslySetInnerHTML?: { __html: string };
}

/** Props for Anchor mock component */
export interface MockAnchorProps extends MockComponentProps {
  href?: string;
  target?: string;
}

// ============================================================================
// Interactive Components
// ============================================================================

/** Props for Button mock component */
export interface MockButtonProps extends MockComponentProps {
  kind?: string;
  onClick?: MouseEventHandler;
  disabled?: boolean;
  "aria-label"?: string;
}

/** Props for Tooltip mock component */
export interface MockTooltipProps extends MockComponentProps {
  slotContent?: ReactNode;
}

/** Props for Popover mock component */
export interface MockPopoverProps extends MockComponentProps {
  slotTrigger?: ReactNode;
  slotContent?: ReactNode;
}

/** Props for Checkbox mock component */
export interface MockCheckboxProps extends MockComponentProps {
  checked?: boolean;
  onCheckedChange?: (checked: boolean) => void;
  slotLabel?: ReactNode;
}

// ============================================================================
// Display Components
// ============================================================================

/** Props for Badge mock component */
export interface MockBadgeProps extends MockComponentProps {
  color?: string;
  kind?: string;
  title?: string;
}

/** Props for Divider mock component */
export interface MockDividerProps extends MockComponentProps {
  orientation?: string;
}

/** Props for StatusMessage mock component */
export interface MockStatusMessageProps extends MockComponentProps {
  slotHeading?: ReactNode;
  slotSubheading?: ReactNode;
  slotMedia?: ReactNode;
  size?: string;
}

// ============================================================================
// Container Components
// ============================================================================

/** Props for Panel mock component */
export interface MockPanelProps extends MockComponentProps {
  slotHeading?: ReactNode;
  slotFooter?: ReactNode;
  elevation?: string;
}

/** Props for SidePanel mock component */
export interface MockSidePanelProps extends MockComponentProps {
  slotHeading?: ReactNode;
  open?: boolean;
  onInteractOutside?: () => void;
  modal?: boolean;
  hideCloseButton?: boolean;
}

/** Props for Notification mock component */
export interface MockNotificationProps extends MockComponentProps {
  status?: string;
  slotHeading?: ReactNode;
  slotSubheading?: ReactNode;
  slotFooter?: ReactNode;
}

/** Props for PageHeader mock component */
export interface MockPageHeaderProps extends MockComponentProps {
  slotHeading?: ReactNode;
  slotSubheading?: ReactNode;
  slotActions?: ReactNode;
}

// ============================================================================
// Navigation Components
// ============================================================================

/** Props for AppBar mock component */
export interface MockAppBarProps extends MockComponentProps {
  slotLeft?: ReactNode;
  slotRight?: ReactNode;
}

/** Props for AppBarLogo mock component */
export interface MockAppBarLogoProps extends MockComponentProps {
  size?: string;
}

// ============================================================================
// Form Components
// ============================================================================

/** Single item for SegmentedControl */
export interface MockSegmentedControlItem {
  children: ReactNode;
  value: string;
}

/** Props for SegmentedControl mock component */
export interface MockSegmentedControlProps extends MockComponentProps {
  items: MockSegmentedControlItem[];
  value: string;
  onValueChange?: (value: string) => void;
  size?: string;
}

// ============================================================================
// Accordion Components
// ============================================================================

/** Single item for Accordion */
export interface MockAccordionItem {
  slotTrigger: ReactNode;
  slotContent: ReactNode;
  value: string;
}

/** Props for Accordion mock component */
export interface MockAccordionProps extends MockComponentProps {
  items: MockAccordionItem[];
  value?: string;
  onValueChange?: (value: string) => void;
}

// ============================================================================
// Tabs Components
// ============================================================================

/** Single item for Tabs */
export interface MockTabItem {
  children?: ReactNode;
  slotTrigger?: ReactNode;
  slotContent?: ReactNode;
  value: string;
}

/** Props for Tabs mock component */
export interface MockTabsProps extends MockComponentProps {
  items: MockTabItem[];
  value?: string;
  onValueChange?: (value: string) => void;
}

// ============================================================================
// DefconBadge specific
// ============================================================================

/** Props for DefconBadge mock component */
export interface MockDefconBadgeProps extends MockComponentProps {
  defcon: number | null | undefined;
  size?: "sm" | "md" | "lg" | "xl";
  showLabel?: boolean;
}

// ============================================================================
// ECharts Mock Types
// ============================================================================

/** Mock ECharts option structure */
export interface MockEChartsOption {
  tooltip?: {
    position?: (point: number[], params: unknown, dom: HTMLElement) => [number, number];
    formatter?: (params: unknown) => string;
  };
  yAxis?: {
    data?: string[];
    axisLabel?: {
      formatter?: (value: string, index: number) => string;
    };
  };
  series?: Array<{
    data?: Array<{
      value?: number;
      name?: string;
      label?: {
        formatter?: (params: { value: number }) => string;
      };
    }>;
  }>;
}

/** Props for ECharts mock component */
export interface MockEChartsProps {
  option?: MockEChartsOption;
  onEvents?: {
    click?: (params: { name: string }) => void;
  };
}
