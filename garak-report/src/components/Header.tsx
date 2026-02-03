/**
 * @file Header.tsx
 * @description Application header with logo and theme toggle button.
 * @module components
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { AppBar, Button, Flex, Tooltip } from "@kui/react";
import { Moon, Sun } from "lucide-react";
import GarakLogo from "./GarakLogo";

/** Props for the Header component */
interface HeaderProps {
  onThemeToggle?: () => void;
  isDark?: boolean;
}

/**
 * Application header component with branding and theme controls.
 *
 * @param props - Component props
 * @param props.onThemeToggle - Optional callback for theme toggle button
 * @param props.isDark - Current theme state for icon display
 * @returns Sticky header with logo and optional theme toggle
 */
const Header = ({ onThemeToggle, isDark = false }: HeaderProps) => {
  return (
    <AppBar
      style={{ position: "sticky", top: 0, zIndex: 1000 }}
      slotLeft={<GarakLogo />}
      slotRight={
        <Flex gap="density-xs" align="center">
          {onThemeToggle && (
            <Tooltip slotContent={isDark ? "Switch to light mode" : "Switch to dark mode"}>
              <Button
                kind="tertiary"
                onClick={onThemeToggle}
                aria-label={isDark ? "Switch to light mode" : "Switch to dark mode"}
              >
                {isDark ? <Sun size={20} /> : <Moon size={20} />}
              </Button>
            </Tooltip>
          )}
        </Flex>
      }
    />
  );
};

export default Header;
