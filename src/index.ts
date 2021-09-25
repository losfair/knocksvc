/// <reference path="../node_modules/jsland-types/src/index.d.ts" />

import { JTDSchemaType } from "jsland-types/src/validation/jtd";

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

Router.get(
  "/",
  (req) =>
    new Response(
      `
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<p>Your IP address is ${req.headers.get("x-rw-client-ip")}.</p>
<p><a href="/current">List of currently authenticated services</a></p>
<p><a href="/enter">Enter</a></p>
<p><a href="/leave">Leave</a></p>
<p>Knocksvc | <a href="https://univalence.me">Univalence Labs</a></p>
</body>
</html>
  `.trim(),
      {
        headers: {
          "Content-Type": "text/html",
        },
      }
    )
);

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

Router.get("/current", async (request) => {
  const clientIp = request.headers.get("x-rw-client-ip");
  if (!clientIp) throw new Error("missing client ip");

  const svclist = (
    await appDB.exec(
      "select svcname from ipgrant where ipaddr = :ip and created_at > :earliest and active = 1",
      {
        ip: ["s", clientIp],
        earliest: ["d", new Date(Date.now() - ttlMs)],
      },
      "s"
    )
  ).map((x) => x[0]);

  return new Response(JSON.stringify(svclist, null, 2), {
    headers: {
      "Content-Type": "application/json",
    },
  });
});

Router.get("/leave", async (request) => {
  const clientIp = request.headers.get("x-rw-client-ip");
  if (!clientIp) throw new Error("missing client ip");

  await appDB.exec(
    "update ipgrant set active = 0 where ipaddr = :ip and created_at > :earliest",
    {
      ip: ["s", clientIp],
      earliest: ["d", new Date(Date.now() - ttlMs)],
    },
    ""
  );
  return new Response("ok");
});

Router.get("/enter", async (request) => {
  const clientIp = request.headers.get("x-rw-client-ip");
  if (!clientIp) throw new Error("missing client ip");

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  if (!code) {
    const urlInfo = ghApp.getWebFlowAuthorizationUrl({
      scopes: ["user:email"],
    });
    return Response.redirect(urlInfo.url, 302);
  }

  const tokenInfo = await ghApp.createToken({ code });
  const octokit = new ExternalService.GitHub.Octokit({
    auth: tokenInfo.authentication.token,
    userAgent: "knocksvc on rwv2 by z@univalence.me",
  });
  const emailList = await octokit.rest.users.listEmailsForAuthenticated();
  const verifiedEmails = emailList.data
    .filter((x) => x.verified)
    .map((x) => x.email);
  const grantInfo: Record<string, string[]> = {};

  await appDB.startTransaction();
  for (const email of verifiedEmails) {
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
        await appDB.exec(
          "insert into ipgrant (ipaddr, svcname) values(:ip, :svc)",
          {
            ip: ["s", clientIp],
            svc: ["s", svcname],
          },
          ""
        );
        if (!grantInfo[svcname]) grantInfo[svcname] = [];
        grantInfo[svcname].push(email);
      }
    }
  }
  await appDB.commit();

  return new Response(JSON.stringify(grantInfo, null, 2), {
    headers: {
      "Content-Type": "application/json",
    },
  });
});
