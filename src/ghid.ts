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

export function ensureAuthenticatedGhid(
  req: Request,
  redirectBack: boolean = false
): GhidInfo | Response {
  const ghidInfo = getAuthenticatedGhid(req);
  if (typeof ghidInfo === "string") {
    const target = new URL("/ghlogin", req.url);
    if (redirectBack) target.searchParams.set("callback", req.url);
    return new Response(null, {
      status: 302,
      headers: {
        location: target.toString(),
        "x-reason": ghidInfo,
      },
    });
  }
  return ghidInfo;
}
