/**
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { view, largeView, option } from "./heatmapFixtures";
import TestHeatmap from "./HeatmapHarness";
import { render, screen, fireEvent, act } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
describe("heatmap keyboard", () => {
  it("leaves the chart intact on pointer focus and reveals focus when a key is used", () => {
    render(<TestHeatmap view={view} />);
    const grid = screen.getByRole("grid");
    vi.spyOn(grid, "matches").mockReturnValue(false);
    const before = option;
    fireEvent.focus(grid);
    expect(option, "pointer focus cannot redraw the tile before its click completes").toBe(before);
    fireEvent.keyDown(grid, { key: "ArrowRight" });
    expect(
      option.graphic.elements[1].ignore,
      "keyboard navigation still displays the active cell"
    ).toBe(false);
  });
  it("selects and clears a cell without a pointer", () => {
    const select = vi.fn();
    render(<TestHeatmap view={view} onSelect={select} />);
    const grid = screen.getByRole("grid");
    act(() => grid.focus());
    expect(grid, "active result has an accessible identity").toHaveAttribute(
      "aria-activedescendant"
    );
    expect(
      screen.getByRole("gridcell"),
      "the visual low-count cue also reaches screen readers"
    ).toHaveTextContent("Low evaluation count");
    fireEvent.keyDown(grid, { key: "Enter" });
    expect(select).toHaveBeenLastCalledWith({ axis: "cell", technique: "t1", intent: "i1" });
    fireEvent.keyDown(grid, { key: " " });
    expect(select, "Space toggles the same result").toHaveBeenLastCalledWith(null);
    fireEvent.keyDown(grid, { key: "Enter" });
    fireEvent.keyDown(grid, { key: "Escape" });
    expect(select, "Escape clears selection").toHaveBeenLastCalledWith(null);
  });
  it.each([
    ["ArrowUp", "intent", "i1"],
    ["ArrowLeft", "technique", "t1"],
  ])("selects an axis through %s", (key, axis, id) => {
    const select = vi.fn();
    render(<TestHeatmap view={view} onSelect={select} />);
    const grid = screen.getByRole("grid");
    fireEvent.keyDown(grid, { key });
    fireEvent.keyDown(grid, { key: "Enter" });
    expect(select, "headers support the same activation as cells").toHaveBeenLastCalledWith({
      axis,
      key: id,
    });
  });
  it("announces missing results without selecting them", () => {
    const select = vi.fn();
    render(<TestHeatmap view={view} onSelect={select} />);
    const grid = screen.getByRole("grid");
    fireEvent.keyDown(grid, { key: "ArrowRight" });
    expect(screen.getByRole("gridcell"), "missing is not zero").toHaveTextContent("Not evaluated");
    fireEvent.keyDown(grid, { key: "Enter" });
    expect(select).not.toHaveBeenCalled();
  });
  it("pans a zoomed window to follow keyboard navigation", () => {
    render(<TestHeatmap view={largeView(20)} />);
    fireEvent.click(screen.getByRole("button", { name: "Zoom in" }));
    fireEvent.keyDown(screen.getByRole("grid"), { key: "End" });
    expect(
      screen.getByText("1 techniques · Intents 11–20 of 20"),
      "the active cell remains visible"
    ).toBeVisible();
    fireEvent.keyDown(screen.getByRole("grid"), { key: "Home" });
    expect(screen.getByText("1 techniques · Intents 1–10 of 20")).toBeVisible();
  });
});
