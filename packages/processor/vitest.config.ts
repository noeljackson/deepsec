import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "processor",
    include: ["src/__tests__/**/*.test.ts"],
  },
});
