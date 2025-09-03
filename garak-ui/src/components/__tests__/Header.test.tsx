import { render, screen } from "@testing-library/react";
import Header from "../Header";
import { vi, describe, it, expect } from "vitest";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  AppBar: ({ slotLeft, ...props }: any) => (
    <header data-testid="app-bar" {...props}>
      {slotLeft}
    </header>
  ),
  AppBarLogo: ({ size, ...props }: any) => (
    <div data-testid="app-bar-logo" data-size={size} {...props}>
      Logo
    </div>
  ),
  Text: ({ children, kind, ...props }: any) => (
    <span data-kind={kind} {...props}>
      {children}
    </span>
  ),
}));

describe("Header", () => {
  it("renders the logo and title", () => {
    render(<Header />);
    expect(screen.getByTestId("app-bar-logo")).toBeInTheDocument();
    expect(screen.getByText("GARAK")).toBeInTheDocument();
  });

  it("uses correct AppBar structure", () => {
    render(<Header />);
    expect(screen.getByTestId("app-bar")).toBeInTheDocument();
  });

  it("uses small logo size", () => {
    render(<Header />);
    const logo = screen.getByTestId("app-bar-logo");
    expect(logo).toHaveAttribute("data-size", "small");
  });
});
