import { defineConfig, setLoadedConfig } from "@deepsec/core";
import { afterEach, describe, expect, it } from "vitest";
import { resolveAgentType } from "../resolve-agent-type.js";

describe("resolveAgentType", () => {
  afterEach(() => {
    setLoadedConfig(defineConfig({ projects: [] }));
  });

  it("returns the user-provided value when given", () => {
    setLoadedConfig(defineConfig({ projects: [], defaultAgent: "codex" }));
    expect(resolveAgentType("claude-agent-sdk")).toBe("claude-agent-sdk");
  });

  it("falls back to defaultAgent from config when not provided", () => {
    setLoadedConfig(defineConfig({ projects: [], defaultAgent: "codex" }));
    expect(resolveAgentType(undefined)).toBe("codex");
  });

  it("falls back to claude-agent-sdk when neither is set", () => {
    setLoadedConfig(defineConfig({ projects: [] }));
    expect(resolveAgentType(undefined)).toBe("claude-agent-sdk");
  });
});
