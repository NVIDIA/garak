import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import SetupSection from "../SetupSection";
import { vi, describe, it, expect, beforeEach } from "vitest";

// Shared mock instance
const formatValueMock = vi.fn((val: unknown) => String(val));

vi.mock("../hooks/useValueFormatter", () => ({
  useValueFormatter: () => ({
    formatValue: formatValueMock,
  }),
}));

const longText = "a".repeat(100);

const setup = {
  "a.copy_me": longText,
  "plugins.model_type": "transformer",
  "plugins.model_name": "gpt-x",
  "transient.run_id": "abc-123",
  "transient.starttime_iso": "2025-06-26T10:00:00Z",
};

const findStrongText = (label: string) => (content: string, el?: Element | null) =>
  el?.tagName === "STRONG" && content.trim().toLowerCase().startsWith(label.toLowerCase());

beforeEach(() => {
  Object.assign(navigator, {
    clipboard: {
      writeText: vi.fn().mockResolvedValue(undefined),
    },
  });

  formatValueMock.mockImplementation((val: unknown) => String(val));
});

describe("SetupSection", () => {
  it("renders grouped sections by prefix", () => {
    render(<SetupSection setup={setup} />);
    expect(screen.getByText("plugins")).toBeInTheDocument();
    expect(screen.getByText("transient")).toBeInTheDocument();
  });

  it("expands only the first section by default", () => {
    render(<SetupSection setup={setup} />);
    expect(screen.getByText("copy me:")).toBeInTheDocument();
    expect(screen.queryByText("model type:")).toBeNull();
  });

  it("toggles section open and closed on click", () => {
    render(<SetupSection setup={setup} />);
    const btn = screen.getByText("transient");
    fireEvent.click(btn);
    expect(screen.getByText(findStrongText("run id"))).toBeInTheDocument();
    fireEvent.click(btn);
    expect(screen.queryByText(findStrongText("run id"))).toBeNull();
  });

  it("formats values using formatValue hook", () => {
    render(<SetupSection setup={setup} />);
    fireEvent.click(screen.getByText("plugins"));
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

  it("copies to clipboard and shows temporary success indicator", async () => {
    render(<SetupSection setup={{ "a.copy_me": longText }} />);
    const copyBtn = screen.getByLabelText("copy to clipboard");
    fireEvent.click(copyBtn);
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(longText);
    expect(await screen.findByText("✅")).toBeInTheDocument();
    await waitFor(
      () => {
        expect(screen.queryByText("✅")).toBeNull();
      },
      { timeout: 2500 }
    );
  });

  it("logs a warning if clipboard copy fails", async () => {
    Object.assign(navigator, {
      clipboard: {
        writeText: vi.fn().mockRejectedValue(new Error("fail")),
      },
    });

    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    render(<SetupSection setup={{ "a.copy_me": longText }} />);
    const copyBtn = screen.getByLabelText("copy to clipboard");
    fireEvent.click(copyBtn);
    await waitFor(() => {
      expect(warnSpy).toHaveBeenCalledWith("❌ Clipboard copy failed:", expect.any(Error));
    });
    warnSpy.mockRestore();
  });

  it("sets title to the string value if display is a string", () => {
    render(<SetupSection setup={{ "a.field": "hello" }} />);
    const span = screen.getByText("hello");
    expect(span).toHaveAttribute("title", "hello");
  });

  it("sets title to empty string when display is not a string", async () => {
    vi.resetModules();

    vi.doMock("../../hooks/useValueFormatter", () => ({
      useValueFormatter: () => ({
        formatValue: () => 42, // non-string result
      }),
    }));

    const { default: SetupSectionNonString } = await import("../SetupSection");

    render(<SetupSectionNonString setup={{ "a.field": "ignored" }} />);
    const span = screen.getByText("42");
    expect(span).toHaveAttribute("title", "");
  });
});
