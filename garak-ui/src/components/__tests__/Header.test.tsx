import { render, screen } from "@testing-library/react";
import Header from "../Header";
import { vi, describe, it, expect } from "vitest";

// Mock logo
vi.mock("../logo.svg?react", () => ({
  default: () => <div data-testid="logo">Logo</div>,
}));

describe("ReportHeader", () => {
  it("renders the logo and title", () => {
    render(<Header />);
    expect(screen.getByTestId("logo")).toBeInTheDocument();
    expect(screen.getByText("garak")).toBeInTheDocument();
  });
});
