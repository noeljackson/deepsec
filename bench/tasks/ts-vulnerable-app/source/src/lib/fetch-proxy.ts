import { Request, Response } from "express";

export async function proxyRequest(req: Request, res: Response) {
  const response = await fetch(req.query.url as string);
  res.json(await response.json());
}

export async function fetchHealthcheck() {
  return fetch("https://status.example.com/health");
}
