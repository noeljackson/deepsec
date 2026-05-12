import type { MatcherPlugin } from "./types.js";

export class MatcherRegistry {
  private matchers = new Map<string, MatcherPlugin>();

  register(plugin: MatcherPlugin): void {
    this.matchers.set(plugin.slug, plugin);
  }

  getAll(): MatcherPlugin[] {
    return Array.from(this.matchers.values());
  }

  getBySlug(slug: string): MatcherPlugin | undefined {
    return this.matchers.get(slug);
  }

  getBySlugs(slugs: string[]): MatcherPlugin[] {
    return slugs
      .map((s) => this.matchers.get(s))
      .filter((m): m is MatcherPlugin => m !== undefined);
  }

  slugs(): string[] {
    return Array.from(this.matchers.keys());
  }
}
