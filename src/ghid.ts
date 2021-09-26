import { verify } from "./signature";
import { parse } from "cookie";

export interface GhidInfo {
  login: string;
  emails: string[];
}

export function getAuthenticatedGhid(req: Request): GhidInfo | string {
  const cookie = parse(req.headers.get("Cookie") || "");
  const payload = verify(cookie["knock-ghid"] || "");
  if (typeof payload === "string") return payload;
  if (payload.type !== "ghid") return "not-ghid";
  return payload;
}

export function ensureAuthenticatedGhid(req: Request): GhidInfo | Response {
  const ghidInfo = getAuthenticatedGhid(req);
  if (typeof ghidInfo === "string")
    return new Response(null, {
      status: 302,
      headers: {
        location: "/ghlogin",
        "x-reason": ghidInfo,
      },
    });
  return ghidInfo;
}
