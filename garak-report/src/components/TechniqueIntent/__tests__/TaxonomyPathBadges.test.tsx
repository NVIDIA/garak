/**
 * @file TaxonomyPathBadges.test.tsx
 * @description Verifies the breadcrumb rendering for a technique's full
 *              taxonomy path (Issue #1972): every branch segment renders as a
 *              tag, in order, and single-segment keys render nothing.
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import TaxonomyPathBadges from "../TaxonomyPathBadges";
import type { MockBadgeProps, MockFlexProps, MockTextProps } from "../../../test-utils/mockTypes";

// Reuse the same gray-outline Badge the Probes tag list renders with, so this
// test only asserts on content/order, not on KUI's internals.
vi.mock("@kui/react", () => ({
  Badge: ({ children, color, kind }: MockBadgeProps) => (
    <span data-testid="badge" data-color={color} data-kind={kind}>
      {children}
    </span>
  ),
  Flex: ({ children }: MockFlexProps) => <div>{children}</div>,
  Text: ({ children }: MockTextProps) => <span>{children}</span>,
}));

describe("TaxonomyPathBadges", () => {
  it("renders every branch segment, broadest first, down to the leaf", () => {
    render(<TaxonomyPathBadges techniqueKey="demon:Fictionalizing:Roleplaying:User_persona" />);
    const badges = screen.getAllByTestId("badge");
    expect(badges.map(b => b.textContent)).toEqual(["Fictionalizing", "Roleplaying", "User_persona"]);
  });

  it("uses the same gray outline tag styling as the Probes tag list", () => {
    render(<TaxonomyPathBadges techniqueKey="demon:Encoding:Base64" />);
    for (const badge of screen.getAllByTestId("badge")) {
      expect(badge.dataset.color).toBe("gray");
      expect(badge.dataset.kind).toBe("outline");
    }
  });

  it("renders nothing for a single-segment key (no hierarchy to show)", () => {
    const { container } = render(<TaxonomyPathBadges techniqueKey="demon:Base64" />);
    expect(container).toBeEmptyDOMElement();
  });
});
