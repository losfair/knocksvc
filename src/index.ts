/// <reference path="../node_modules/jsland-types/src/index.d.ts" />

import { JTDSchemaType } from "jsland-types/src/validation/jtd";
import {
  ensureAuthenticatedGhid,
  getAuthenticatedGhid,
  GhidInfo,
} from "./ghid";
import { exportPubkey, sign } from "./signature";
import "./tmpgrant";

const ghClientId = App.mustGetEnv("ghClientId");
const ghClientSecret = App.mustGetEnv("ghClientSecret");
const ghApp = new ExternalService.GitHub.OAuthApp({
  clientId: ghClientId,
  clientSecret: ghClientSecret,
});
const appDB = App.mysql.db;
const ttlMs = 86400 * 1000;

interface SvcQuery {
  svcname: string;
  svcsecret: string;
  userip: string;
}

const schema_SvcQuery: JTDSchemaType<SvcQuery> = {
  properties: {
    svcname: { type: "string" },
    svcsecret: { type: "string" },
    userip: { type: "string" },
  },
};
const validator_SvcQuery = new Validation.JTD.JTDStaticSchema(schema_SvcQuery);

Router.get("/", async (req) => {
  const clientIp = req.headers.get("x-rw-client-ip") || "";
  const ghidInfo = getAuthenticatedGhid(req);
  return new Response(
    Template.render(
      `
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<p>Your IP address: <code>{{ clientIp }}</code></p>
<p>Server pubkey: <code>{{ pubKey }}</code></p>
<p>Authenticated services by IP: <code>{{ authlist }}</code></p>
<p>
GitHub ID: <code>{{ ghid }}</code> <a href="/ghlogin">relogin</a>
</p>
<p>Authenticated services by GitHub ID: <code>{{ grantList }}</code></p>
<p>
<form method="post" action="/enter">
  <span>Authenticate this IP address</span>
  <button type="submit">Enter</button>
</form>
<form method="post" action="/ghlogout">
  <span>Reset GitHub login status</span>
  <button type="submit">Logout</button>
</form>
<form method="post" action="/revoke">
  <span>Revoke all IP grants associated with this GitHub ID</span>
  <button type="submit">Revoke</button>
</form>
</p>
<hr>
<p>Knocksvc | <a href="https://univalence.me">Univalence Labs</a></p>
</body>
</html>
  `.trim(),
      {
        clientIp,
        pubKey: exportPubkey(),
        authlist: (await getSvclistByClientIp(clientIp)).join(", "),
        ghid:
          typeof ghidInfo === "string" ? "[" + ghidInfo + "]" : ghidInfo.login,
        grantList:
          typeof ghidInfo === "string"
            ? ""
            : (await getGrantListByGrantby(ghidInfo.login))
                .map((x) => x.ipaddr + "/" + x.svcname)
                .join(", "),
      }
    ),
    {
      headers: {
        "Content-Type": "text/html",
      },
    }
  );
});

Router.get("/pub", (req) => {
  return new Response(exportPubkey());
});

Router.post("/query", async (request) => {
  const body = await request.json();
  if (!validator_SvcQuery.validate(body))
    return new Response(validator_SvcQuery.lastError, {
      status: 400,
    });

  {
    const row = (
      await appDB.exec(
        "select svcsecret from svclist where svcname = :n",
        {
          n: ["s", body.svcname],
        },
        "s"
      )
    )[0];
    if (!row || row[0] !== body.svcsecret)
      return new Response("service not found or secrets do not match", {
        status: 403,
      });
  }

  const row = (
    await appDB.exec(
      "select 1 from ipgrant where ipaddr = :ip and created_at > :earliest and svcname = :svc and active = 1",
      {
        ip: ["s", body.userip],
        svc: ["s", body.svcname],
        earliest: ["d", new Date(Date.now() - ttlMs)],
      },
      "i"
    )
  )[0];
  const ok = !!row;

  return new Response(
    JSON.stringify({
      ok,
    }),
    {
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
});

async function getSvclistByClientIp(clientIp: string): Promise<string[]> {
  const svclist = (
    await appDB.exec(
      "select distinct svcname from ipgrant where ipaddr = :ip and created_at > :earliest and active = 1",
      {
        ip: ["s", clientIp],
        earliest: ["d", new Date(Date.now() - ttlMs)],
      },
      "s"
    )
  ).map((x) => x[0]!);
  return svclist;
}

async function getGrantListByGrantby(
  by: string
): Promise<{ ipaddr: string; svcname: string }[]> {
  const list = (
    await appDB.exec(
      `
      select ipaddr, svcname from ipgrant
        where grantby = :by
          and created_at > :earliest
          and active = 1
          group by ipaddr, svcname
      `,
      {
        by: ["s", by],
        earliest: ["d", new Date(Date.now() - ttlMs)],
      },
      "ss"
    )
  ).map(([ipaddr, svcname]) => ({
    ipaddr: ipaddr!,
    svcname: svcname!,
  }));
  return list;
}

Router.get("/current", async (request) => {
  const clientIp = request.headers.get("x-rw-client-ip");
  if (!clientIp) throw new Error("missing client ip");

  return new Response(
    JSON.stringify(await getSvclistByClientIp(clientIp), null, 2),
    {
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
});

Router.post("/ghlogout", async (request) => {
  return new Response(null, {
    status: 302,
    headers: {
      location: "/",
      "set-cookie": "knock-ghid=; Expires=" + new Date(0).toUTCString(),
    },
  });
});

Router.get("/ghlogin", async (request) => {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const callback = url.searchParams.get("callback") || "";
  if (!code) {
    const redirectUrl = new URL("/ghlogin", request.url);
    if (callback) redirectUrl.searchParams.set("callback", callback);
    const urlInfo = ghApp.getWebFlowAuthorizationUrl({
      scopes: ["user:email"],
      redirectUrl: redirectUrl.toString(),
    });
    return Response.redirect(urlInfo.url, 302);
  }

  const tokenInfo = await ghApp.createToken({ code });
  const octokit = new ExternalService.GitHub.Octokit({
    auth: tokenInfo.authentication.token,
    userAgent: "knocksvc on rwv2 by z@univalence.me",
  });
  const [user, emailList] = await Promise.all([
    octokit.rest.users.getAuthenticated(),
    octokit.rest.users.listEmailsForAuthenticated(),
  ]);
  const verifiedEmails = emailList.data
    .filter((x) => x.verified)
    .map((x) => x.email);

  const ghidInfo: GhidInfo = {
    login: user.data.login,
    emails: verifiedEmails,
  };
  const signed = sign(
    {
      type: "ghid",
      ...ghidInfo,
    },
    3600 * 1000
  );
  return new Response(null, {
    status: 302,
    headers: {
      location: callback.startsWith(`https://${url.host}/`) ? callback : "/",
      "set-cookie": `knock-ghid=${signed}; Secure; HttpOnly; Path=/; SameSite=Lax`,
    },
  });
});

Router.post("/revoke", async (request) => {
  const clientIp = request.headers.get("x-rw-client-ip");
  if (!clientIp) throw new Error("missing client ip");

  const ghidInfo = ensureAuthenticatedGhid(request);
  if (ghidInfo instanceof Response) return ghidInfo;

  await appDB.exec(
    "update ipgrant set active = 0 where grantby = :login and created_at > :earliest",
    {
      login: ["s", ghidInfo.login],
      earliest: ["d", new Date(Date.now() - ttlMs)],
    },
    ""
  );
  return Response.redirect("/", 302);
});

Router.get("/enter_crypto", async (request) => {
  const ghidInfo = ensureAuthenticatedGhid(request, true);
  if (ghidInfo instanceof Response) return ghidInfo;

  const url = new URL(request.url);
  const svcname = url.searchParams.get("svcname");
  if (!svcname) return new Response("missing svcname");
  const callback = url.searchParams.get("callback");
  if (!callback) return new Response("missing callback");
  const referrer = request.headers.get("referer") || "";

  return new Response(
    Template.render(
      `
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<p>Referrer: {{ referrer }}<br>Callback: {{ callback }}</p>
<form method="post">
  <span>Cryptographically authenticate service <strong>{{ svcname }}</strong> with GHID <strong>{{ ghid }}</strong></span>
  <button type="submit">OK</button>
</form>
</body>
</html>
  `.trim(),
      {
        referrer,
        callback,
        svcname,
        ghid: ghidInfo.login,
      }
    ),
    {
      headers: {
        "content-type": "text/html",
      },
    }
  );
});

Router.post("/enter_crypto", async (request) => {
  const ghidInfo = ensureAuthenticatedGhid(request);
  if (ghidInfo instanceof Response) return ghidInfo;

  const url = new URL(request.url);
  const svcname = url.searchParams.get("svcname");
  if (!svcname) return new Response("missing svcname");
  const callback = url.searchParams.get("callback");
  if (!callback) return new Response("missing callback");
  const callbackUrl = new URL(callback);
  let ok = false;

  for (const email of ghidInfo.emails) {
    const allowed = (
      await appDB.exec(
        "select 1 from allowlist where email = :email and svcname = :svcname",
        {
          email: ["s", email],
          svcname: ["s", svcname],
        },
        "i"
      )
    )[0];
    if (allowed) {
      ok = true;
      break;
    }
  }

  if (ok) {
    const signed = sign(
      {
        type: "svcgrant",
        svcname,
      },
      86400 * 1000
    );
    callbackUrl.searchParams.set("__knocksvc_grant", signed);
    return Response.redirect(callbackUrl.toString(), 302);
  } else {
    return new Response("permission denied", {
      status: 403,
    });
  }
});

Router.post("/enter", async (request) => {
  const clientIp = request.headers.get("x-rw-client-ip");
  if (!clientIp) throw new Error("missing client ip");

  const ghidInfo = ensureAuthenticatedGhid(request);
  if (ghidInfo instanceof Response) return ghidInfo;

  const grantInfo: Record<string, boolean> = {};

  await appDB.startTransaction();
  for (const email of ghidInfo.emails) {
    const allowedServices = await appDB.exec(
      "select svcname from allowlist where email = :email",
      {
        email: ["s", email],
      },
      "s"
    );
    for (const row of allowedServices) {
      const [svcname] = row;
      if (svcname) {
        if (!grantInfo[svcname]) {
          grantInfo[svcname] = true;
          await appDB.exec(
            "insert into ipgrant (ipaddr, svcname, grantby) values(:ip, :svc, :gb)",
            {
              ip: ["s", clientIp],
              svc: ["s", svcname],
              gb: ["s", ghidInfo.login],
            },
            ""
          );
        }
      }
    }
  }
  await appDB.commit();
  return Response.redirect("/", 302);
});

// CSRF protection
Router.use("/", async (req, next) => {
  if (req.method === "POST") {
    const url = new URL(req.url);
    if (url.pathname !== "/query") {
      if (req.headers.get("origin") !== "https://" + url.host) {
        return new Response("bad origin", {
          status: 403,
        });
      }
    }
  }
  return next(req);
});
