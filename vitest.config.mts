import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const rootDir = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  test: {
    environment: "node",
    maxWorkers: 4,
    include: ["tests/unit/**/*.test.ts", "tests/integration/**/*.test.ts"],
    coverage: { reporter: ["text", "html"], include: ["lib/**/*.ts"] }
  },
  resolve: { alias: { "@": rootDir } }
});
