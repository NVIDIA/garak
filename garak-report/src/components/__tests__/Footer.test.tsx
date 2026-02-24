import { render, screen } from "@testing-library/react";
import Footer from "../Footer";
import { describe, it, expect, vi } from "vitest";
import type {
  MockFlexProps,
  MockPopoverProps,
  MockButtonProps,
  MockStackProps,
  MockTextProps,
  MockAnchorProps,
} from "../../test-utils/mockTypes";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Flex: ({ children, ...props }: MockFlexProps) => (
    <div data-testid="flex" {...props}>
      {children}
    </div>
  ),
  Popover: ({ children, slotContent, ...props }: MockPopoverProps) => (
    <div data-testid="popover" {...props}>
      {children}
      <div data-testid="popover-content" style={{ display: "none" }}>
        {slotContent}
      </div>
    </div>
  ),
  Button: ({ children, onClick, kind, ...props }: MockButtonProps) => (
    <button onClick={onClick} data-kind={kind} {...props}>
      {children}
    </button>
  ),
  Stack: ({ children, ...props }: MockStackProps) => (
    <div data-testid="stack" {...props}>
      {children}
    </div>
  ),
  Text: ({ children, kind, ...props }: MockTextProps) => (
    <span data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Anchor: ({ children, href, target, ...props }: MockAnchorProps) => (
    <a href={href} target={target} {...props}>
      {children}
    </a>
  ),
}));

describe("Footer", () => {
  it("renders static text and link", () => {
    render(<Footer />);
    expect(screen.getByText(/Generated with/i)).toBeInTheDocument();
    expect(screen.getByText(/garak/i)).toBeInTheDocument();
  });

  it("has correct garak link", () => {
    render(<Footer />);
    const link = screen.getByText("garak");
    expect(link).toHaveAttribute("href", "https://github.com/NVIDIA/garak");
    expect(link).toHaveAttribute("target", "_blank");
  });

  it("has correct test id for footer text", () => {
    render(<Footer />);
    const footerText = screen.getByTestId("footer-garak");
    expect(footerText).toBeInTheDocument();
  });

  it("renders with correct padding and alignment", () => {
    const { container } = render(<Footer />);
    const flex = container.querySelector('[data-testid="flex"]');
    expect(flex).toHaveAttribute("padding", "density-2xl");
    expect(flex).toHaveAttribute("justify", "center");
    expect(flex).toHaveAttribute("align", "center");
  });
});
