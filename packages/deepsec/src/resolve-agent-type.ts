import { getConfig } from "@deepsec/core";

/**
 * Resolve the agent backend from CLI input or the loaded config.
 *
 * Precedence:
 *   1. The `--agent` value the user passed (always wins).
 *   2. `defaultAgent` from deepsec.config.ts.
 *   3. `claude-agent-sdk`.
 */
export function resolveAgentType(provided: string | undefined): string {
  return provided ?? getConfig()?.defaultAgent ?? "claude-agent-sdk";
}
