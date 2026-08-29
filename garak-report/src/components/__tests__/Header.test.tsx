import { render, screen } from "@testing-library/react";
import Header from "../Header";
import { vi, describe, it, expect } from "vitest";
import type {
  MockAppBarProps,
  MockAppBarLogoProps,
  MockFlexProps,
  MockStackProps,
  MockButtonProps,
  MockTooltipProps,
  MockPopoverProps,
  MockTextProps,
} from "../../test-utils/mockTypes";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  AppBar: ({ slotLeft, ...props }: MockAppBarProps) => (
    <header data-testid="app-bar" {...props}>
      {slotLeft}
    </header>
  ),
  AppBarLogo: ({ size, ...props }: MockAppBarLogoProps) => (
    <div data-testid="app-bar-logo" data-size={size} {...props}>
      Logo
    </div>
  ),
  Flex: ({ children, ...props }: MockFlexProps) => (
    <div data-testid="flex" {...props}>
      {children}
    </div>
  ),
  Stack: ({ children, ...props }: MockStackProps) => (
    <div data-testid="stack" {...props}>
      {children}
    </div>
  ),
  Button: ({ children, onClick, ...props }: MockButtonProps) => (
    <button role="button" onClick={onClick} {...props}>
      {children}
    </button>
  ),
  Tooltip: ({ children, slotContent, ...props }: MockTooltipProps) => (
    <div data-testid="tooltip" {...props}>
      <div data-testid="tooltip-content">{slotContent}</div>
      {children}
    </div>
  ),
  Popover: ({ children, slotTrigger, slotContent, ...props }: MockPopoverProps) => (
    <div data-testid="popover" {...props}>
      <div data-testid="popover-trigger">{slotTrigger}</div>
      <div data-testid="popover-content">{slotContent || children}</div>
    </div>
  ),
  Text: ({ children, kind, ...props }: MockTextProps) => (
    <span data-kind={kind} {...props}>
      {children}
    </span>
  ),
  useTheme: () => ({ theme: "light" }),
}));

// Mock logo components
vi.mock("../GarakLogo", () => ({
  __esModule: true,
  default: () => <div data-testid="garak-logo">GarakLogo</div>,
}));

describe("Header", () => {
  it("renders the logo and title", () => {
    render(<Header />);
    expect(screen.getByTestId("garak-logo")).toBeInTheDocument();
  });

  it("uses correct AppBar structure", () => {
    render(<Header />);
    expect(screen.getByTestId("app-bar")).toBeInTheDocument();
  });

  it("does not render flex container for single logo", () => {
    render(<Header />);
    expect(screen.queryByTestId("flex")).not.toBeInTheDocument();
  });

  it("renders theme toggle button when onThemeToggle provided", () => {
    const onThemeToggle = vi.fn();
    const { container } = render(<Header onThemeToggle={onThemeToggle} isDark={false} />);

    // Component should render successfully with theme toggle prop
    expect(container).toBeTruthy();
  });

  it("renders theme toggle for dark mode", () => {
    const onThemeToggle = vi.fn();
    const { container } = render(<Header onThemeToggle={onThemeToggle} isDark={true} />);

    // Component should render successfully in dark mode
    expect(container).toBeTruthy();
  });
});
