import { render, screen, fireEvent } from "@testing-library/react";
import SetupSection from "../SetupSection";
import { vi, describe, it, expect } from "vitest";

// Mock useValueFormatter
vi.mock("../hooks/useValueFormatter", () => ({
  useValueFormatter: () => ({
    formatValue: (val: unknown) => String(val),
  }),
}));

const setup = {
  "plugins.model_type": "transformer",
  "plugins.model_name": "gpt-x",
  "transient.run_id": "abc-123",
  "transient.starttime_iso": "2025-06-26T10:00:00Z",
};

const findStrongText = (label: string) => (content: string, el?: Element | null) =>
  el?.tagName === "STRONG" && content.trim().toLowerCase().startsWith(label.toLowerCase());

describe("SetupSection", () => {
  it("renders grouped sections by prefix", () => {
    render(<SetupSection setup={setup} />);
    expect(screen.getByText("plugins")).toBeInTheDocument();
    expect(screen.getByText("transient")).toBeInTheDocument();
  });

  it("expands only the first section by default", () => {
    render(<SetupSection setup={setup} />);
    expect(screen.getByText(findStrongText("model type"))).toBeInTheDocument();
    expect(screen.queryByText(findStrongText("run id"))).toBeNull();
  });

  it("toggles section open and closed on click", () => {
    render(<SetupSection setup={setup} />);

    const transientBtn = screen.getByText("transient");
    fireEvent.click(transientBtn);
    expect(screen.getByText(findStrongText("run id"))).toBeInTheDocument();

    fireEvent.click(transientBtn);
    expect(screen.queryByText(findStrongText("run id"))).toBeNull();
  });

  it("formats values using formatValue hook", () => {
    render(<SetupSection setup={setup} />);
    expect(screen.getByText("gpt-x")).toBeInTheDocument();
    expect(screen.getByText("transformer")).toBeInTheDocument();
  });

  it("returns null if no section keys are found", () => {
    const { container } = render(<SetupSection setup={{}} />);
    expect(container.firstChild).toBeNull();
  });

  it("returns null if setup is undefined", () => {
    const { container } = render(<SetupSection setup={undefined as any} />);
    expect(container.firstChild).toBeNull();
  });

  it("ignores invalid setup keys", () => {
    const badSetup = {
      badkey: "should be ignored",
      "plugins.model_name": "gpt-x",
    };

    render(<SetupSection setup={badSetup} />);
    expect(screen.getByText("plugins")).toBeInTheDocument();
    expect(screen.queryByText("badkey")).toBeNull();
  });
});
