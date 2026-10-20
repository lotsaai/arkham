// Demo API server. Validates the REAL token only; the client container
// holds just the deterministic fake. Listeners:
//   8443  HTTPS (HTTP semantics)          - MITM path, https:// grant
//   8000  cleartext HTTP                  - MITM path, http:// grant
//         + token issuer: discovery and client_credentials exchange
//   9000  cleartext TCP line protocol     - raw substitution, tcp:// grant
//   9443  TLS line protocol               - MITM + raw substitution, https:// grant
//   9444  TLS line protocol, no grant     - spliced untouched by arkham
const REAL = process.env.ARKHAM_REAL ?? "";
const CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET ?? "";
const ACCESS_TOKEN = process.env.OIDC_ACCESS_TOKEN ?? "";
const CERT_DIR = process.env.CERT_DIR ?? "/certs";
if (!REAL) {
  console.error("ARKHAM_REAL not set");
  process.exit(1);
}

const tls = { cert: Bun.file(`${CERT_DIR}/api.crt`), key: Bun.file(`${CERT_DIR}/api.key`) };

const fetch = (req: Request) => {
  const auth = req.headers.get("authorization") ?? "";
  console.log(`req ${req.url} auth=${auth.slice(0, 14)}…`);
  if (auth === `Bearer ${REAL}`) {
    return new Response(`token:${REAL}\n`);
  }
  // A minted access token: arkham swapped the client-held decoy for the
  // real one. The body never echoes the access token, because minted
  // decoys are swapped on requests, not redacted from arbitrary response
  // positions.
  if (auth === `Bearer ${ACCESS_TOKEN}`) {
    return new Response(`ok\n`);
  }
  return new Response(`unauthorized:${auth}\n`, { status: 401 });
};

Bun.serve({
  hostname: "0.0.0.0",
  port: 8443,
  tls,
  fetch,
});

// Token issuer on the cleartext HTTP leg: discovery plus a
// client_credentials exchange gated on the real client secret (Basic auth).
// arkham swaps the client's fake secret to the real one here, mints a decoy
// for the returned access token, and swaps that decoy back on later
// requests.
const issuerFetch = (req: Request) => {
  const url = new URL(req.url);
  if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
    return Response.json({
      issuer: "http://api:8000",
      token_endpoint: "http://api:8000/token",
      grant_types_supported: ["client_credentials", "authorization_code"],
    });
  }
  if (req.method === "POST" && url.pathname === "/token") {
    if (!CLIENT_SECRET || !ACCESS_TOKEN) {
      console.error("OIDC_CLIENT_SECRET or OIDC_ACCESS_TOKEN not set");
      return Response.json({ error: "invalid_client" }, { status: 401 });
    }
    const auth = req.headers.get("authorization") ?? "";
    const expected = `Basic ${Buffer.from(`demo-client:${CLIENT_SECRET}`).toString("base64")}`;
    if (auth !== expected) {
      return Response.json({ error: "invalid_client" }, { status: 401 });
    }
    return Response.json({
      access_token: ACCESS_TOKEN,
      token_type: "Bearer",
      expires_in: 3600,
    });
  }
  return new Response("not found\n", { status: 404 });
};

// Plain HTTP twin for the http:// grant scenario (transparent capture).
// Issuer paths first, then the bearer-checked API.
Bun.serve({
  hostname: "0.0.0.0",
  port: 8000,
  fetch: (req: Request) => {
    const pathname = new URL(req.url).pathname;
    if (pathname === "/.well-known/openid-configuration" || pathname === "/token") {
      return issuerFetch(req);
    }
    return fetch(req);
  },
});

type LineState = { buf: string };
const lineHandlers = {
  data(socket: Bun.Socket<LineState>, chunk: Buffer) {
    socket.data.buf += chunk.toString();
    let nl = socket.data.buf.indexOf("\n");
    while (nl >= 0) {
      const line = socket.data.buf.slice(0, nl);
      socket.data.buf = socket.data.buf.slice(nl + 1);
      const m = /^AUTH (.*)$/.exec(line);
      const token = m?.[1] ?? "";
      console.log(`auth token=${token.slice(0, 14)}…`);
      socket.write(token === REAL ? `OK ${REAL}\n` : `ERR ${token}\n`);
      nl = socket.data.buf.indexOf("\n");
    }
  },
};
Bun.listen<LineState>({ hostname: "0.0.0.0", port: 9000, socket: lineHandlers, data: { buf: "" } });
Bun.listen<LineState>({ hostname: "0.0.0.0", port: 9443, tls, socket: lineHandlers, data: { buf: "" } });
Bun.listen<LineState>({ hostname: "0.0.0.0", port: 9444, tls, socket: lineHandlers, data: { buf: "" } });
console.log("api listening: 8443 https, 8000 http+issuer, 9000 tcp, 9443 tls-mitm, 9444 tls-splice");