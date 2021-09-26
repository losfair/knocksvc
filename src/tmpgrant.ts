import { JTDSchemaType } from "jsland-types/src/validation/jtd";

interface TmpGrantReq {
  svcname: string;
  svcsecret: string;
  userip: string;
}

const schema_TmpGrantReq: JTDSchemaType<TmpGrantReq> = {
  properties: {
    svcname: { type: "string" },
    svcsecret: { type: "string" },
    userip: { type: "string" },
  },
};

const validator_TmpGrantReq = new Validation.JTD.JTDStaticSchema(
  schema_TmpGrantReq
);

Router.post("/tmpgrant", async (request) => {
  const req: unknown = await request.json();
  if (!validator_TmpGrantReq.validate(req))
    return new Response(validator_TmpGrantReq.lastError, {
      status: 400,
    });
  return new Response();
});
