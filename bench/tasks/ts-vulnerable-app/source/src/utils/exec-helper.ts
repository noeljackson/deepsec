import { exec, execFile } from "node:child_process";

export function listDirectory(req: any) {
  exec(`ls -la ${req.query.path}`);
}

export function listRootSafe() {
  execFile("/bin/ls", ["-la", "/srv/app"]);
}
