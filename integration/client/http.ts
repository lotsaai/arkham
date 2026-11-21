// http scenarios through arkham's transparent capture. The client holds only decoys.
import { connect, Socket } from "node:net";
import { FAKE, OIDC_FAKE_SECRET, race, stage, tlsTo, exchange, retry, ca, finish } from "./lib.ts";
// 1. https:// grant, HTTP over MITM TLS: server must see the real bearer;
//    the redacted body comes back carrying the fake.
await retry("https", "https mitm substitutes request and redacts response", async () => {
  const resp = await race(
    "https echo",
    fetch("https://api:8443/echo", {
      headers: { authorization: `Bearer ${FAKE}` },
      tls: { ca },
    }),
  );
  const body = await race("https echo body", resp.text());
  stage(`http reply: ${JSON.stringify({ status: resp.status, body })}`);
  return resp.status === 200 && body === `token:${FAKE}\n`;
});

// 2. http:// grant, cleartext HTTP through transparent capture: server must
//    see the real bearer; the redacted body comes back carrying the fake.
await retry("http", "http mitm substitutes request and redacts response", async () => {
  const resp = await race(
    "http echo",
    fetch("http://api:8000/echo", {
      headers: { authorization: `Bearer ${FAKE}` },
    }),
  );
  const body = await race("http echo body", resp.text());
  stage(`http reply: ${JSON.stringify({ status: resp.status, body })}`);
  return resp.status === 200 && body === `token:${FAKE}\n`;
});

// 3. tcp:// grant, cleartext raw stream: opaque substitution both ways.
//    Scenarios 3-5 stay on raw sockets. They speak the demo's own AUTH <token> line protocol from integration/api/server.ts, which has no client library.
await retry("tcp", "tcp raw substitutes both directions", async () => {
  stage("tcp api:9000 connecting");
  const sock = await race("tcp api:9000 connect", new Promise<Socket>((resolve, reject) => {
    const s = connect(9000, "api");
    s.once("connect", () => resolve(s));
    s.once("error", reject);
  }));
  stage("tcp api:9000 connected");
  return (await exchange(sock, `AUTH ${FAKE}\n`)) === `OK ${FAKE}\n`;
});

// 4. https:// grant, non-HTTP payload inside MITM TLS: raw machines on the
//    terminated legs.
await retry("https", "tcp over tls mitm substitutes both directions", async () => {
  const tls = await tlsTo("api", 9443, ca);
  return (await exchange(tls, `AUTH ${FAKE}\n`)) === `OK ${FAKE}\n`;
});

// 5. No grant: arkham never terminates the TLS, the handshake passes through
//    to the api server (its own CA-signed leaf verifies), and the fake
//    arrives untouched, so the server rejects it. Empty scheme: this splice
//    covers no `Scheme`.
await retry("", "grantless tls splices untouched", async () => {
  const tls = await tlsTo("api", 9444, ca);
  return (await exchange(tls, `AUTH ${FAKE}\n`)) === `ERR ${FAKE}\n`;
});

// 7. OAuth2 client_credentials through the token issuer: the fake client
//    secret is swapped to the real one at /token, the returned access token
//    is minted as a decoy (never the real value), and that decoy swaps back
//    to the real access token on the API call. Garbage tokens stay
//    unauthorized.
await retry("http", "oauth2 token endpoint mints and the minted decoy substitutes", async () => {
  const basic = Buffer.from(`demo-client:${OIDC_FAKE_SECRET}`).toString("base64");
  const tokenResp = await fetch("http://api:8000/token", {
    method: "POST",
    headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
    body: "grant_type=client_credentials",
  });
  if (tokenResp.status !== 200) {
    stage(`token endpoint status ${tokenResp.status}`);
    return false;
  }
  const { access_token: minted, token_type: tokenType } = (await tokenResp.json()) as { access_token: string; token_type: string };
  stage(`minted token head: ${minted.slice(0, 8)}…`);
  // The minted decoy renders the default {hex:32} pattern; the real access
  // token does not. A regex shape check proves minting fired without the
  // client ever learning the real value.
  if (!/^[0-9a-f]{32}$/.test(minted) || tokenType !== "Bearer" || minted === OIDC_FAKE_SECRET) {
    return false;
  }
  const apiResp = await fetch("http://api:8000/api", { headers: { authorization: `Bearer ${minted}` } });
  if (apiResp.status !== 200 || (await apiResp.text()) !== "ok\n") {
    return false;
  }
  const badResp = await fetch("http://api:8000/api", { headers: { authorization: "Bearer not-a-token" } });
  return badResp.status === 401;
});

await finish();
