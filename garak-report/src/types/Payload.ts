/**
 * @file Payload.ts
 * @description Type definitions for payload metadata.
 * @module types
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

/** Normalized payload object structure */
export type PayloadObject = {
  /** Number of entries in the payload */
  entries: number;
  /** Type of entries (e.g., "prompt", "attack") */
  entry_type: string;
  /** File size in bytes */
  filesize: number;
  /** Loading completion status */
  loading_complete: string;
  /** Last modification time */
  mtime: string;
  /** Display name of the payload */
  payload_name: string;
  /** File system path to the payload */
  payload_path: string;
};

