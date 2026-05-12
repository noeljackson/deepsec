import fs from "node:fs";

export function download(req: any, res: any) {
  const content = fs.readFileSync(req.query.file, "utf8");
  res.send(content);
}

export function downloadPublicAsset(_req: any, res: any) {
  const content = fs.readFileSync("/srv/public/logo.svg", "utf8");
  res.send(content);
}
