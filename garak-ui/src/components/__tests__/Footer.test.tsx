import { render, screen } from "@testing-library/react";
import Footer from "../Footer";
import { describe, it, expect, vi } from "vitest";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Flex: ({ children, ...props }: any) => <div data-testid="flex" {...props}>{children}</div>,
  Popover: ({ children, slotContent, ...props }: any) => (
    <div data-testid="popover" {...props}>
      {children}
      <div data-testid="popover-content" style={{ display: "none" }}>
        {slotContent}
      </div>
    </div>
  ),
  Button: ({ children, onClick, kind, ...props }: any) => (
    <button onClick={onClick} data-kind={kind} {...props}>
      {children}
    </button>
  ),
  Stack: ({ children, ...props }: any) => <div data-testid="stack" {...props}>{children}</div>,
  Text: ({ children, kind, ...props }: any) => <span data-kind={kind} {...props}>{children}</span>,
  Anchor: ({ children, href, target, ...props }: any) => (
    <a href={href} target={target} {...props}>
      {children}
    </a>
  ),
}));

describe("Footer", () => {
  it("renders static text and button", () => {
    render(<Footer />);
    expect(screen.getByText("About this comparison")).toBeInTheDocument();
    expect(screen.getByText(/Generated with/i)).toBeInTheDocument();
    expect(screen.getByText(/garak/i)).toBeInTheDocument();
  });

  it("renders popover with z-score information", () => {
    render(<Footer />);
    
    // Check that the popover contains the expected z-score information
    expect(screen.getByText(/Positive Z-scores mean better than average/i)).toBeInTheDocument();
    expect(screen.getByText(/The middle 10% of models score -0.125 to \+0.125/i)).toBeInTheDocument();
    expect(screen.getByText(/A Z-score of \+1.0 means the score was one standard deviation better/i)).toBeInTheDocument();
  });

  it("has correct button kind", () => {
    render(<Footer />);
    const button = screen.getByText("About this comparison");
    expect(button).toHaveAttribute("data-kind", "secondary");
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
});
