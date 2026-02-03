/**
 * @file main.tsx
 * @description Application entry point. Mounts the React app to the DOM.
 * @module entry
 *
 * @copyright NVIDIA Corporation 2023-2026
 * @license Apache-2.0
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App.tsx";

import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
