/// <reference types="vitest" />
/// <reference types="vite/client" />
/// <reference types="node" />
import { defineConfig as viteDefineConfig, type UserConfig } from "vite";
import { defineConfig as vitestDefineConfig, mergeConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { viteSingleFile } from "vite-plugin-singlefile";
import tailwindcss from "@tailwindcss/vite";
import svgr from "vite-plugin-svgr";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isBuild = process.env.NODE_ENV === "production";
const isExampleBuild = process.env.BUILD_EXAMPLE === "true";

// Plugin to inject example data at build time
function injectExampleData() {
  return {
    name: "inject-example-data",
    transformIndexHtml(html: string) {
      // For production builds (not example), remove the reports.js script tag
      if (isBuild && !isExampleBuild) {
        html = html.replace(/<script src="\/reports\/reports\.js"><\/script>\s*/g, '');
      }
      
      if (isExampleBuild) {
        try {
          const digestPath = path.resolve(__dirname, "public/reports/extracted_digest.json");
          const digestData = fs.readFileSync(digestPath, "utf-8");
          const digestJson = JSON.parse(digestData);
          const dataArray = Array.isArray(digestJson) ? digestJson : [digestJson];
          
          // Inject the data as a global variable before the app loads
          const injectedScript = `<script>window.__GARAK_INSERT_HERE__ = ${JSON.stringify(dataArray)};</script>`;
          return html.replace("</head>", `${injectedScript}\n  </head>`);
        } catch (err) {
          console.error("Failed to load example data:", err);
        }
      }
      return html;
    },
  };
}

// Base Vite config
const viteConfig: UserConfig = viteDefineConfig({
  plugins: [react(), injectExampleData(), viteSingleFile(), tailwindcss(), svgr()],
  publicDir: isBuild ? false : "public",
  build: {
    outDir: isExampleBuild ? "dist" : "../garak/analyze/ui",
    assetsInlineLimit: Infinity,
    cssCodeSplit: false,
    emptyOutDir: false,
  },
  define: isExampleBuild ? {
    __GARAK_INSERT_HERE__: "window.__GARAK_INSERT_HERE__",
  } : {},
});

// Vitest-specific settings
const vitestConfig = vitestDefineConfig({
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "vitest.setup.ts",
    css: false, // Disable CSS processing entirely for tests
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
        "src/assets/**",
        "**/node_modules/**",
        "**/__tests__/**",
        "**/*.test.{ts,tsx}",
        "**/*.spec.{ts,tsx}",
        // Exclude pure SVG components (no logic to test)
        "src/components/GarakLogo.tsx",
        "src/components/NvidiaLogo.tsx",
        // Exclude display-only/low-priority components
        "src/components/MetadataSection.tsx",
        "src/components/SetupSection.tsx",
        "src/hooks/usePayloadParser.ts",
      ],
    },
  },
});

export default mergeConfig(viteConfig, vitestConfig);
