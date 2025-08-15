import "@testing-library/jest-dom";
import { render, screen, fireEvent } from "@testing-library/react";
import ColorLegend from "../ColorLegend";
import { describe, it, expect, vi } from "vitest";

describe("ColorLegend", () => {
  it("renders five severity items", () => {
    render(<ColorLegend />);
    const labels = ["Very Bad", "Below Average", "Average", "Good", "Excellent"];
    labels.forEach(label => expect(screen.getByText(label)).toBeInTheDocument());

    // Each label should have a preceding color square
    const squares = labels.map(l => screen.getByLabelText(l as any));
    expect(squares).toHaveLength(5);
    // Ensure first square has non-empty background color
    const style = window.getComputedStyle(squares[0]);
    expect(style.backgroundColor).not.toBe("");
  });

  it("renders hide button and calls onClose when clicked", () => {
    const onClose = vi.fn();
    render(<ColorLegend onClose={onClose} />);

    const button = screen.getByRole("button", { name: /hide legend/i });
    expect(button).toBeInTheDocument();

    fireEvent.click(button);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does not render hide button when onClose is not provided", () => {
    render(<ColorLegend />);
    const button = screen.queryByRole("button", { name: /hide legend/i });
    expect(button).toBeNull();
  });
}); 