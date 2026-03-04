/**
 * @file SetupSection.ts
 * @description Props type for SetupSection component.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Props for the SetupSection component */
export type SetupSectionProps = {
  /** Garak configuration key-value pairs, or null if unavailable */
  setup: Record<string, unknown> | null;
};
