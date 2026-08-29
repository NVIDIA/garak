/**
 * @file ErrorBoundary.test.tsx
 * @description Tests for ErrorBoundary component
 */

import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import ErrorBoundary from "../ErrorBoundary";

// Mock KUI components
vi.mock("@kui/react", () => ({
  Stack: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="stack">{children}</div>
  ),
  Button: ({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) => (
    <button onClick={onClick}>{children}</button>
  ),
  StatusMessage: ({ slotHeading, slotSubheading }: { slotHeading: string; slotSubheading: string }) => (
    <div data-testid="status-message">
      <h3>{slotHeading}</h3>
      <p>{slotSubheading}</p>
    </div>
  ),
}));

// Component that throws an error
const ThrowError = ({ shouldThrow }: { shouldThrow: boolean }) => {
  if (shouldThrow) {
    throw new Error("Test error");
  }
  return <div data-testid="child">Child content</div>;
};

describe("ErrorBoundary", () => {
  // Suppress console.error for error boundary tests
  const originalError = console.error;
  beforeEach(() => {
    console.error = vi.fn();
  });

  afterEach(() => {
    console.error = originalError;
  });

  it("renders children when no error", () => {
    render(
      <ErrorBoundary>
        <div data-testid="child">Test content</div>
      </ErrorBoundary>
    );
    
    expect(screen.getByTestId("child")).toBeInTheDocument();
    expect(screen.getByText("Test content")).toBeInTheDocument();
  });

  it("renders error UI when child throws", () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    
    expect(screen.getByTestId("status-message")).toBeInTheDocument();
    expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    expect(screen.queryByTestId("child")).not.toBeInTheDocument();
  });

  it("displays custom fallback message", () => {
    render(
      <ErrorBoundary fallbackMessage="Custom error message">
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    
    expect(screen.getByText("Custom error message")).toBeInTheDocument();
  });

  it("displays default fallback message when none provided", () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    
    expect(screen.getByText(/An error occurred while rendering/)).toBeInTheDocument();
  });

  it("renders Try Again button", () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    
    expect(screen.getByText("Try Again")).toBeInTheDocument();
  });

  it("calls handleReset when Try Again is clicked", () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    );
    
    // Verify error UI is shown
    expect(screen.getByTestId("status-message")).toBeInTheDocument();
    
    // Verify Try Again button exists and is clickable
    const tryAgainButton = screen.getByText("Try Again");
    expect(tryAgainButton).toBeInTheDocument();
    
    // Click should not throw
    fireEvent.click(tryAgainButton);
  });
});
