import crypto from "node:crypto";

export function hashPassword(password: string): string {
  return crypto.createHash("md5").update(password).digest("hex");
}

export function issueResetToken(): string {
  const token = Math.random().toString(36).slice(2);
  return token;
}
