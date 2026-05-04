import fs from "node:fs";
import path from "node:path";
import { findProject, getConfigPath, projectConfigPath } from "@deepsec/core";
import { scan } from "@deepsec/scanner";
import { BOLD, DIM, GREEN, RESET } from "../formatters.js";
import { requireExistingDir } from "../require-dir.js";
import { resolveProjectId } from "../resolve-project-id.js";

/**
 * Resolve the root directory to scan, in precedence order:
 *   1. `--root` flag (override; required for first-time scans, sandbox runs)
 *   2. `findProject(id).root` from the loaded `deepsec.config.ts`
 *      (resolved relative to the config file's directory)
 *   3. `data/<id>/project.json:rootPath` from a prior run
 *   4. Throw with actionable guidance.
 *
 * Every resolved path is verified to exist and be a directory.
 */
function resolveScanRoot(opts: { projectId: string; root?: string }): string {
  if (opts.root) {
    return requireExistingDir(opts.root, "--root");
  }

  const projectFromConfig = findProject(opts.projectId);
  const configPath = getConfigPath();
  if (projectFromConfig && configPath) {
    const configDir = path.dirname(configPath);
    const resolved = path.resolve(configDir, projectFromConfig.root);
    return requireExistingDir(resolved, `deepsec.config.ts (${configPath})`);
  }

  const projectJsonPath = projectConfigPath(opts.projectId);
  if (fs.existsSync(projectJsonPath)) {
    const stored = JSON.parse(fs.readFileSync(projectJsonPath, "utf-8"));
    if (typeof stored.rootPath === "string") {
      return requireExistingDir(stored.rootPath, `${projectJsonPath}:rootPath`);
    }
  }

  throw new Error(
    `No root path for project "${opts.projectId}".\n` +
      `  Pass --root <path>, or add the project to deepsec.config.ts:\n` +
      `    projects: [{ id: "${opts.projectId}", root: "<path>" }]`,
  );
}

export async function scanCommand(opts: { projectId?: string; root?: string; matchers?: string }) {
  const projectId = resolveProjectId(opts.projectId);
  const matcherSlugs = opts.matchers ? opts.matchers.split(",").map((s) => s.trim()) : undefined;
  const resolvedRoot = resolveScanRoot({ projectId, root: opts.root });

  console.log(`${BOLD}Scanning${RESET} ${resolvedRoot} for project ${BOLD}${projectId}${RESET}`);
  if (matcherSlugs) {
    console.log(`${DIM}Matchers: ${matcherSlugs.join(", ")}${RESET}`);
  }
  console.log();

  const result = await scan({
    projectId,
    root: resolvedRoot,
    matcherSlugs,
    onProgress(progress) {
      switch (progress.type) {
        case "matcher_started":
          console.log(`${DIM}  Running: ${progress.matcherSlug}${RESET}`);
          break;
        case "matcher_done":
          console.log(`  ${progress.matcherSlug}: ${progress.matchCount} match(es)`);
          break;
        case "file_scanned":
          break;
      }
    },
  });

  console.log();
  console.log(
    `${GREEN}Scan complete.${RESET} Run: ${BOLD}${result.runId}${RESET}  Candidates: ${result.candidateCount}`,
  );
  console.log();
  console.log(`Next:`);
  console.log(`${DIM}pnpm deepsec process --project-id ${projectId}${RESET}`);
}
