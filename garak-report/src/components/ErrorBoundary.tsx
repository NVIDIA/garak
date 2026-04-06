/**
 * @file ErrorBoundary.tsx
 * @description React error boundary component for graceful error handling.
 *              Catches render errors and displays a fallback UI.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { Component, ErrorInfo, ReactNode } from "react";
import { Stack, Button, StatusMessage } from "@kui/react";

/** Props for ErrorBoundary component */
interface Props {
  children: ReactNode;
  fallbackMessage?: string;
}

/** Internal state for error tracking */
interface State {
  /** Whether an error has been caught */
  hasError: boolean;
  /** The caught error object, if any */
  error: Error | null;
}

/**
 * Error boundary component that catches JavaScript errors in child components.
 * Displays a fallback UI and optional retry button when errors occur.
 *
 * @example
 * ```tsx
 * <ErrorBoundary fallbackMessage="Chart failed to load">
 *   <ProbesChart {...props} />
 * </ErrorBoundary>
 * ```
 */
class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Silent fallback - errors are logged only to state
    // In production, this could be sent to an error tracking service
    this.setState({ error });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <Stack gap="density-md" paddingTop="density-2xl" paddingBottom="density-2xl">
          <StatusMessage
            size="medium"
            slotHeading="Something went wrong"
            slotSubheading={
              this.props.fallbackMessage ||
              "An error occurred while rendering this component. Please refresh the page."
            }
          />
          <Button kind="secondary" onClick={this.handleReset}>
            Try Again
          </Button>
        </Stack>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
