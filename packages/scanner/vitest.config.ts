import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "scanner",
    include: ["src/__tests__/**/*.test.ts"],
  },
});
