import { render, screen } from "@testing-library/react";
import SetupSection from "../SetupSection";
import { vi, describe, it, expect } from "vitest";
import type {
  MockTabsProps,
  MockTabItem,
  MockTextProps,
  MockStackProps,
  MockFlexProps,
} from "../../test-utils/mockTypes";

// Mock Kaizen components
vi.mock("@kui/react", () => ({
  Tabs: ({ items }: MockTabsProps) => (
    <div data-testid="tabs">
      {items.map((item: MockTabItem, index: number) => (
        <div key={index} data-testid={`tab-${index}`}>
          <div data-testid={`tab-trigger-${index}`}>{item.children}</div>
          <div data-testid={`tab-content-${index}`}>{item.slotContent}</div>
        </div>
      ))}
    </div>
  ),
  Text: ({ children, kind, ...props }: MockTextProps) => (
    <span data-kind={kind} {...props}>
      {children}
    </span>
  ),
  Stack: ({ children, ...props }: MockStackProps) => (
    <div data-testid="stack" {...props}>
      {children}
    </div>
  ),
  Flex: ({ children, ...props }: MockFlexProps) => (
    <div data-testid="flex" {...props}>
      {children}
    </div>
  ),
}));

// Mock useValueFormatter hook
vi.mock("../../hooks/useValueFormatter", () => ({
  useValueFormatter: () => ({
    formatValue: (val: unknown) => {
      if (Array.isArray(val)) return val.map(String);
      return String(val);
    },
  }),
}));

const setup = {
  "plugins.model_type": "transformer",
  "plugins.model_name": "gpt-x",
  "transient.run_id": "abc-123",
  "transient.starttime_iso": "2025-06-26T10:00:00Z",
  "config.num_layers": 12,
};

const setupWithArrays = {
  "plugins.model_type": "transformer",
  "features.enabled": ["feature1", "feature2", "feature3"],
};

describe("SetupSection", () => {
  it("renders grouped sections by prefix", () => {
    render(<SetupSection setup={setup} />);
    expect(screen.getByText("plugins")).toBeInTheDocument();
    expect(screen.getByText("transient")).toBeInTheDocument();
    expect(screen.getByText("config")).toBeInTheDocument();
  });

  it("renders setup field content in tabs", () => {
    render(<SetupSection setup={setup} />);

    // Check plugins section
    expect(screen.getByText("model type:")).toBeInTheDocument();
    expect(screen.getByText("transformer")).toBeInTheDocument();
    expect(screen.getByText("model name:")).toBeInTheDocument();
    expect(screen.getByText("gpt-x")).toBeInTheDocument();

    // Check transient section
    expect(screen.getByText("run id:")).toBeInTheDocument();
    expect(screen.getByText("abc-123")).toBeInTheDocument();
    expect(screen.getByText("starttime iso:")).toBeInTheDocument();

    // Check config section
    expect(screen.getByText("num layers:")).toBeInTheDocument();
    expect(screen.getByText("12")).toBeInTheDocument();
  });

  it("handles array values correctly", () => {
    render(<SetupSection setup={setupWithArrays} />);

    expect(screen.getByText("enabled:")).toBeInTheDocument();
    expect(screen.getByText("feature1")).toBeInTheDocument();
    expect(screen.getByText("feature2")).toBeInTheDocument();
    expect(screen.getByText("feature3")).toBeInTheDocument();
  });

  it("replaces underscores with spaces in section names", () => {
    const setupWithUnderscores = {
      "model_config.learning_rate": 0.01,
      "training_params.batch_size": 32,
    };

    render(<SetupSection setup={setupWithUnderscores} />);
    expect(screen.getByText("model config")).toBeInTheDocument();
    expect(screen.getByText("training params")).toBeInTheDocument();
    expect(screen.getByText("learning rate:")).toBeInTheDocument();
    expect(screen.getByText("batch size:")).toBeInTheDocument();
  });

  it("returns null if no section keys are found", () => {
    const { container } = render(<SetupSection setup={{}} />);
    expect(container.firstChild).toBeNull();
  });

  it("returns null if setup is undefined", () => {
    // @ts-expect-error: testing fallback when setup is undefined
    const { container } = render(<SetupSection setup={undefined} />);
    expect(container.firstChild).toBeNull();
  });

  it("ignores invalid setup keys without dots", () => {
    const badSetup = {
      badkey: "should be ignored",
      "plugins.model_name": "gpt-x",
    };
    render(<SetupSection setup={badSetup} />);
    expect(screen.getByText("plugins")).toBeInTheDocument();
    expect(screen.getByText("gpt-x")).toBeInTheDocument();
    expect(screen.queryByText("badkey")).toBeNull();
  });

  it("renders correct tab structure", () => {
    render(<SetupSection setup={setup} />);
    expect(screen.getByTestId("tabs")).toBeInTheDocument();
    expect(screen.getByTestId("tab-0")).toBeInTheDocument(); // plugins
    expect(screen.getByTestId("tab-1")).toBeInTheDocument(); // transient
    expect(screen.getByTestId("tab-2")).toBeInTheDocument(); // config
  });
});
