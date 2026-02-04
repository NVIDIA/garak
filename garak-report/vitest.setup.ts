import { expect, afterEach, vi } from "vitest";
import * as matchers from "@testing-library/jest-dom/matchers";
import { cleanup } from "@testing-library/react";

expect.extend(matchers);
afterEach(() => {
  cleanup();
});

// Mock CSS imports
vi.mock("*.css", () => ({}));
vi.mock("*.min.css", () => ({}));
vi.mock("*.scss", () => ({}));

// Mock ResizeObserver for tests
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
};
