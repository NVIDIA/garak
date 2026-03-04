/**
 * @file usePayloadParser.ts
 * @description Hook to parse and normalize payload metadata from various formats.
 *              Handles JSON strings, Python dict syntax, and hybrid formats.
 * @module hooks
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { useMemo } from "react";
import type { PayloadObject } from "../types/Payload";

// Re-export for backward compatibility
export type { PayloadObject } from "../types/Payload";

/** Input type for payload data (string or already-parsed object) */
type PayloadInput = string | PayloadObject;

/**
 * Type guard to check if a value is a valid parsed payload object.
 * @param value - Value to check
 * @returns True if value has the expected payload structure
 */
function isValidParsedPayload(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Safely extracts a string property from an unknown object.
 * @param obj - Object to extract from
 * @param key - Property key
 * @param fallback - Default value if property is not a string
 * @returns The string value or fallback
 */
function getString(obj: Record<string, unknown>, key: string, fallback: string): string {
  const val = obj[key];
  return typeof val === "string" ? val : fallback;
}

/**
 * Safely extracts a number property from an unknown object.
 * @param obj - Object to extract from
 * @param key - Property key
 * @param fallback - Default value if property is not a number
 * @returns The number value or fallback
 */
function getNumber(obj: Record<string, unknown>, key: string, fallback: number): number {
  const val = obj[key];
  return typeof val === "number" ? val : fallback;
}

/**
 * Builds a PayloadObject from parsed data with safe defaults.
 * @param data - Parsed data object
 * @param fallbackName - Fallback name if payload_name is missing
 * @returns Complete PayloadObject
 */
function buildPayload(data: Record<string, unknown>, fallbackName: string): PayloadObject {
  return {
    payload_name: getString(data, "payload_name", fallbackName),
    entries: getNumber(data, "entries", 0),
    filesize: getNumber(data, "filesize", 0),
    entry_type: getString(data, "entry_type", "unknown"),
    loading_complete: getString(data, "loading_complete", "unknown"),
    mtime: getString(data, "mtime", ""),
    payload_path: getString(data, "payload_path", ""),
  };
}

/**
 * Creates an error payload when parsing fails.
 * @param rawValue - Original string that failed to parse
 * @returns PayloadObject with error indicators
 */
function createErrorPayload(rawValue: string): PayloadObject {
  return {
    payload_name: rawValue.substring(0, 50),
    entries: 0,
    filesize: 0,
    entry_type: "parse_error",
    loading_complete: "unknown",
    mtime: "",
    payload_path: "Parse error",
  };
}

/**
 * Parses payload metadata from various formats into a standardized structure.
 *
 * The backend may send payload data as:
 * - JSON strings with Python dict syntax (single quotes, True/False/None)
 * - Plain objects
 * - Hybrid "name {dict}" format
 *
 * This hook normalizes all formats and deduplicates by payload name.
 *
 * @param payloads - Array of payload data in various formats
 * @returns Normalized array of payload objects with consistent structure
 */
export const usePayloadParser = (payloads?: PayloadInput[]) => {
  return useMemo(() => {
    if (!payloads || payloads.length === 0) return [];

    const parsed = payloads.map(payload => {
      if (typeof payload === "string") {
        try {
          // The string format is: "name {dict}" but can have newlines
          // First normalize the string by removing newlines within the dict
          const normalized = payload.replace(/\n\s*/g, " ");

          // Extract the name and the dict part
          const match = normalized.match(/^(\S+)\s+(\{.+\})$/);
          if (match) {
            const [, name, dictStr] = match;
            // Convert Python dict syntax to JSON (single quotes to double quotes)
            const jsonStr = dictStr
              .replace(/'/g, '"')
              .replace(/True/g, "true")
              .replace(/False/g, "false")
              .replace(/None/g, "null");

            const parsedData: unknown = JSON.parse(jsonStr);
            if (isValidParsedPayload(parsedData)) {
              return buildPayload(parsedData, name);
            }
            return createErrorPayload(payload);
          }

          // Fallback: try parsing as pure JSON
          const fallbackData: unknown = JSON.parse(payload.replace(/'/g, '"'));
          if (isValidParsedPayload(fallbackData)) {
            return buildPayload(fallbackData, "unknown");
          }
          return createErrorPayload(payload);
        } catch {
          // If it's a string but not parseable, create a minimal object
          return createErrorPayload(payload);
        }
      }
      return payload;
    });

    // Return unique payloads by name
    return parsed.reduce((acc: PayloadObject[], payload) => {
      if (!acc.some(p => p.payload_name === payload.payload_name)) {
        acc.push(payload);
      }
      return acc;
    }, []);
  }, [payloads]);
};
