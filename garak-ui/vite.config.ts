/// <reference types="vitest" />
/// <reference types="vite/client" />
import { defineConfig as viteDefineConfig, type UserConfig } from "vite";
import { defineConfig as vitestDefineConfig, mergeConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";
import tailwindcss from "@tailwindcss/vite";
import svgr from "vite-plugin-svgr";

const isBuild = process.env.NODE_ENV === "production";

// Base Vite config
const viteConfig: UserConfig = viteDefineConfig({
  plugins: [react(), viteSingleFile(), tailwindcss(), svgr()],
  publicDir: isBuild ? false : "public",
  build: {
    outDir: "../garak/analyze/ui",
    assetsInlineLimit: Infinity,
    cssCodeSplit: false,
    emptyOutDir: false,
  },
});

// Vitest-specific settings
const vitestConfig = vitestDefineConfig({
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "vitest.setup.ts",
    css: false, // Disable CSS processing entirely for tests
    transformMode: {
      web: [/\.[jt]sx?$/],
      ssr: [/\.css$/],
    },
    coverage: {
      provider: "v8",
      all: true,
      reporter: ["text", "lcov"],
      thresholds: {
        lines: 85,
        functions: 85,
        branches: 85,
        statements: 85,
      },
      exclude: [
        "eslint.config.js",
        "vite.config.ts",
        "public/**",
        "src/App.tsx",
        "src/main.tsx",
        "src/vite-env.d.ts",
        "src/types/**",
        "dist/reports/**",
        "**/assets/package/dist/base/**",
      ],
    },
  },
});

export default mergeConfig(viteConfig, vitestConfig);
