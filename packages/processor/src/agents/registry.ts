import type { AgentPlugin } from "./types.js";

export class AgentRegistry {
  private agents = new Map<string, AgentPlugin>();

  register(plugin: AgentPlugin): void {
    this.agents.set(plugin.type, plugin);
  }

  get(type: string): AgentPlugin | undefined {
    return this.agents.get(type);
  }

  types(): string[] {
    return Array.from(this.agents.keys());
  }
}
