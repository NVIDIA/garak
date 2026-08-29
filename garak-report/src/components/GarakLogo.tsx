/**
 * @file GarakLogo.tsx
 * @description Garak logo component with theme-aware color inversion.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import React from "react";
import { useTheme } from "@kui/react";
import garakLogo from "../assets/garak.svg";

/** Props for GarakLogo component */
interface GarakLogoProps {
  height?: string;
  alt?: string;
}

/**
 * Garak logo image with automatic light/dark theme adaptation.
 * Inverts colors in light mode to maintain visibility.
 *
 * @param props - Component props
 * @param props.height - Logo height (CSS value)
 * @param props.alt - Alt text for accessibility
 * @returns Themed logo image element
 */
export default function GarakLogo({
  height = "20px",
  alt = "Garak Logo",
}: GarakLogoProps): React.ReactElement {
  const { theme } = useTheme();

  return (
    <img
      src={garakLogo}
      alt={alt}
      style={{
        height,
        filter: theme === "light" ? "invert(1)" : "none",
      }}
    />
  );
}
