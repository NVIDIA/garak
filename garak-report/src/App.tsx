/**
 * @file App.tsx
 * @description Root application component. Manages theme state and provides
 *              the KUI ThemeProvider context to the entire application.
 * @module app
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { ThemeProvider } from "@kui/react";
import { useState, useEffect } from "react";
import Report from "./pages/Report";

/**
 * Root application component that manages theme persistence and provides
 * the theme context to all child components.
 *
 * @returns The themed application wrapper
 */
function App() {
  const [theme, setTheme] = useState<"light" | "dark" | "system">("system");

  // Load theme from localStorage on mount
  useEffect(() => {
    const savedTheme = localStorage.getItem("kui-theme") as "light" | "dark" | "system" | null;
    if (savedTheme) {
      setTheme(savedTheme);
    }
  }, []);

  // Save theme to localStorage when it changes
  const handleThemeChange = (newTheme: "light" | "dark" | "system") => {
    setTheme(newTheme);
    localStorage.setItem("kui-theme", newTheme);
  };

  // Manually apply theme class to html element since global prop might not work
  useEffect(() => {
    const htmlElement = document.documentElement;

    // Remove all theme classes
    htmlElement.classList.remove("nv-dark", "nv-light");

    // Add the appropriate theme class
    if (theme === "dark") {
      htmlElement.classList.add("nv-dark");
    } else if (theme === "light") {
      htmlElement.classList.add("nv-light");
    } else if (theme === "system") {
      // Check system preference
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      htmlElement.classList.add(prefersDark ? "nv-dark" : "nv-light");
    }
  }, [theme]);

  return (
    <ThemeProvider theme={theme}>
      <Report onThemeChange={handleThemeChange} currentTheme={theme} />
    </ThemeProvider>
  );
}

export default App;
