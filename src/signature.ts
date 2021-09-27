import { GhidInfo } from "./ghid";

interface SignedData {
  sig: string;
  payload: string;
}

type SignaturePayload = SignaturePayloadData & {
  expiry: number;
};

type SignaturePayloadData =
  | {
      type: "tmpgrant";
      by: string;
    }
  | ({
      type: "ghid";
    } & GhidInfo)
  | {
      type: "svcgrant";
      svcname: string;
    };

const secKey = new NativeCrypto.Ed25519.SecretKey(
  Codec.b64decode(App.mustGetEnv("sigSecret"))
);
const pubKey = new NativeCrypto.Ed25519.PublicKey(secKey);
const keypair = new NativeCrypto.Ed25519.Keypair(secKey, pubKey);

export function exportPubkey(): string {
  return Codec.b64encode(pubKey.exportPublic());
}

export function sign(data: SignaturePayloadData, ttlMs: number): string {
  const expiry = Date.now() + ttlMs;
  const payloadObj: SignaturePayload = {
    expiry,
    ...data,
  };
  const payload = JSON.stringify(payloadObj);
  const sig = Codec.b64encode(
    keypair.sign(new TextEncoder().encode(payload)),
    "urlsafe-nopad"
  );
  return (
    sig +
    ":" +
    Codec.b64encode(new TextEncoder().encode(payload), "urlsafe-nopad")
  );
}

export function verify(
  rawData: string
): SignaturePayload | "invalid-data" | "invalid-signature" | "expired" {
  const rawSegs = rawData.split(":");
  const data: SignedData = {
    sig: rawSegs[0] || "",
    payload: rawSegs[1] || "",
  };

  try {
    data.payload = new TextDecoder().decode(
      Codec.b64decode(data.payload, "urlsafe-nopad")
    );
    if (
      !pubKey.verify(
        Codec.b64decode(data.sig, "urlsafe-nopad"),
        new TextEncoder().encode(data.payload),
        true
      )
    ) {
      return "invalid-signature";
    }
  } catch (e) {
    return "invalid-signature";
  }

  const payload: SignaturePayload = JSON.parse(data.payload);
  if (payload.expiry < Date.now()) {
    return "expired";
  }

  return payload;
}
