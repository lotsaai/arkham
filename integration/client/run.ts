// Demo client. Shares arkham's network namespace; arkham's transparent capture
// takes every connection. The client knows nothing about the proxy:
// it just talks to api by hostname. It holds ONLY the fake token; every
// passing scenario proves arkham swapped it for the real one (and redacted
// replies). Hard bounds everywhere: 5s per network await, 20s per scenario
// except the NATS scenarios, which run once, and 90s for the whole run.
// The first failure ends the run.
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { connect, Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { homedir } from "node:os";
import { join } from "node:path";
import amqplib from "amqplib";
import { RedisClient } from "bun";
import { Client } from "ldapts";
import { connect as natsConnect, StringCodec, credsAuthenticator, nkeyAuthenticator, type Authenticator, type NatsConnection } from "nats";
import rhea from "rhea";

const FAKE = process.env.ARKHAM_FAKE ?? "";
const OIDC_FAKE_SECRET = process.env.OIDC_FAKE_SECRET ?? "";
const CERT_DIR = process.env.CERT_DIR ?? "/certs";
const PG_URL = process.env.DATABASE_URL ?? ""; // the fake connection string
const REDIS_URL = process.env.REDIS_URL ?? "";
const REDIS_TLS_URL = process.env.REDIS_TLS_URL ?? "";
const SMTP_URL = process.env.SMTP_URL ?? "";
const SMTPS_URL = process.env.SMTPS_URL ?? "";
const LDAP_URL = process.env.LDAP_URL ?? "";
const LDAP_TLS_URL = process.env.LDAP_TLS_URL ?? "";
const LDAP_REAL = "arkham_real_ldap_pass_01";
const NATS_URL = process.env.NATS_URL ?? "";
const NATS_REAL = "arkham_real_nats_pass";
const NATS_NKEY_URL = process.env.NATS_NKEY_URL ?? "";
const NATS_JWT_URL = process.env.NATS_JWT_URL ?? "";
const NATS_NKEY_FOREIGN = process.env.NATS_NKEY_FOREIGN ?? "";
const NATS_JWT_FOREIGN_SEED = process.env.NATS_JWT_FOREIGN_SEED ?? "";
const NATS_JWT_FOREIGN_JWT = process.env.NATS_JWT_FOREIGN_JWT ?? "";
const AMQP_URL = process.env.AMQP_URL ?? "";
const AMQP_TLS_URL = process.env.AMQP_TLS_URL ?? "";
const AMQP_REAL = "arkham_real_amqp_pass_longer_01";
const ATTEMPT_TIMEOUT_MS = 5000;
const SCENARIO_BUDGET_MS = 20000;
const TOTAL_BUDGET_MS = 90000;
const DEADLINE = Date.now() + TOTAL_BUDGET_MS;

if (!FAKE || !OIDC_FAKE_SECRET) {
  console.error("ARKHAM_FAKE or OIDC_FAKE_SECRET not set");
  process.exit(1);
}

function outOfTime() {
  return Date.now() > DEADLINE;
}

function race<T>(what: string, p: Promise<T>): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`${what}: timed out after ${ATTEMPT_TIMEOUT_MS}ms`)), ATTEMPT_TIMEOUT_MS).unref?.();
    }),
  ]);
}

function stage(what: string) {
  process.stderr.write(`[${new Date().toISOString().slice(17, 23)}] ${what}\n`);
}

async function tlsTo(host: string, port: number, ca: Buffer): Promise<TLSSocket> {
  stage(`tls ${host}:${port} connecting`);
  const tls = tlsConnect({ host, port, servername: host, ca, rejectUnauthorized: true });
  await race(`tls ${host}:${port} handshake`, new Promise<void>((resolve, reject) => {
    tls.once("secureConnect", () => resolve());
    tls.once("error", reject);
  }));
  stage(`tls ${host}:${port} handshake ok`);
  return tls;
}

function exchange(sock: Socket | TLSSocket, payload: string): Promise<string> {
  return race("line reply", new Promise<string>((resolve, reject) => {
    let buf = "";
    const onData = (c: Buffer) => {
      buf += c.toString();
      if (buf.includes("\n")) {
        sock.off("data", onData);
        sock.destroy();
        resolve(buf);
      }
    };
    sock.once("error", reject);
    sock.on("data", onData);
    sock.write(payload);
  }));
}

async function readAll(sock: Socket | TLSSocket): Promise<string> {
  return race("http reply", new Promise<string>((resolve, reject) => {
    let buf = "";
    sock.on("data", (c: Buffer) => {
      buf += c.toString();
    });
    sock.once("end", () => resolve(buf));
    sock.once("error", reject);
  }));
}

const covered = new Set<string>();

async function once(scheme: string, what: string, fn: () => Promise<boolean>) {
  if (outOfTime()) {
    console.error(`FAIL ${what}: out of time`);
    process.exit(1);
  }
  stage(`${what} attempt 1`);
  try {
    if (await fn()) {
      if (scheme) covered.add(scheme);
      console.log(`PASS ${what}`);
      return;
    }
    console.error(`FAIL ${what}: assertion false`);
  } catch (err) {
    const last = String(err);
    stage(`${what} error: ${last}`);
    console.error(`FAIL ${what}: ${last}`);
  }
  process.exit(1);
}

async function retry(scheme: string, what: string, fn: () => Promise<boolean>) {
  const deadline = Date.now() + SCENARIO_BUDGET_MS;
  let last = "no attempt completed";
  for (let attempt = 1; attempt <= 100; attempt++) {
    if (Date.now() > deadline || outOfTime()) {
      console.error(`FAIL ${what}: ${last}`);
      process.exit(1);
    }
    try {
      stage(`${what} attempt ${attempt}`);
      if (await fn()) {
        if (scheme) covered.add(scheme);
        console.log(`PASS ${what}`);
        return;
      }
      last = "assertion false";
    } catch (err) {
      last = String(err);
      stage(`${what} error: ${last}`);
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  console.error(`FAIL ${what}: ${last}`);
  process.exit(1);
}

const ca = await readFile(`${CERT_DIR}/ca.crt`);

// 1. https:// grant, HTTP over MITM TLS: server must see the real bearer;
//    the redacted body comes back carrying the fake.
await retry("https", "https mitm substitutes request and redacts response", async () => {
  const tls = await tlsTo("api", 8443, ca);
  stage("http request sent");
  tls.write(`GET /echo HTTP/1.1\r\nHost: api\r\nAuthorization: Bearer ${FAKE}\r\nConnection: close\r\n\r\n`);
  const resp = await readAll(tls);
  tls.destroy();
  const status = resp.split("\r\n", 1)[0];
  const body = resp.split("\r\n\r\n", 2)[1] ?? "";
  stage(`http reply: ${JSON.stringify({ status, body })}`);
  return status === "HTTP/1.1 200 OK" && body === `token:${FAKE}\n`;
});

// 2. http:// grant, cleartext HTTP through transparent capture: server must
//    see the real bearer; the redacted body comes back carrying the fake.
await retry("http", "http mitm substitutes request and redacts response", async () => {
  stage("http api:8000 connecting");
  const sock = await race("http api:8000 connect", new Promise<Socket>((resolve, reject) => {
    const s = connect(8000, "api");
    s.once("connect", () => resolve(s));
    s.once("error", reject);
  }));
  sock.write(`GET /echo HTTP/1.1\r\nHost: api\r\nAuthorization: Bearer ${FAKE}\r\nConnection: close\r\n\r\n`);
  const resp = await readAll(sock);
  sock.destroy();
  const status = resp.split("\r\n", 1)[0];
  const body = resp.split("\r\n\r\n", 2)[1] ?? "";
  stage(`http reply: ${JSON.stringify({ status, body })}`);
  return status === "HTTP/1.1 200 OK" && body === `token:${FAKE}\n`;
});

// 3. tcp:// grant, cleartext raw stream: opaque substitution both ways.
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

// 6. Database rule against real PostgreSQL. Gated on DATABASE_URL so this
//    script still runs when that service is absent.
//    The client consumes exactly what the guest holds: its DATABASE_URL,
//    the rule's stated FAKE connection string. Arkham captures the dial,
//    matches the rule on the fake string's port, and swaps the fake
//    password for the real one from the secret source. PostgreSQL rejects
//    the fake password, so an opened session proves the swap. The guest
//    dials by the URL's hostname, and arkham mints the leaf for that name,
//    so full hostname verification stays on — no IPs anywhere.
if (PG_URL) {

  function pgFrame(type: number, body: Buffer): Buffer {
    const len = Buffer.alloc(4);
    len.writeInt32BE(body.length + 4);
    return Buffer.concat([Buffer.from([type]), len, body]);
  }
  function pgStartup(params: Record<string, string>): Buffer {
    const body = Buffer.concat([
      Buffer.from([0, 3, 0, 0]),
      ...Object.entries(params).map(([key, value]) => Buffer.from(`${key}\0${value}\0`, "utf8")),
      Buffer.from([0]),
    ]);
    const len = Buffer.alloc(4);
    len.writeInt32BE(body.length + 4);
    return Buffer.concat([len, body]);
  }
  function pgRead(sock: Socket | TLSSocket, n: number): Promise<Buffer> {
    return race("pg read", new Promise<Buffer>((resolve, reject) => {
      let buf = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length >= n) {
          sock.off("data", onData);
          resolve(buf.subarray(0, n));
        }
      };
      sock.on("data", onData);
      sock.once("error", reject);
    }));
  }
  await retry("postgres", "postgres mitm swaps the password for a real server", async () => {
    const db = new URL(PG_URL);
    stage(`pg ${db.hostname}:${db.port || 5432} connecting`);
    const sock = await race("pg connect", new Promise<Socket>((resolve, reject) => {
      const s = connect(Number(db.port || 5432), db.hostname);
      s.once("connect", () => resolve(s));
      s.once("error", reject);
    }));
    stage("pg sslRequest");
    sock.write(Buffer.from([0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f]));
    const answer = (await pgRead(sock, 1)).toString("latin1");
    if (answer !== "S") throw new Error(`server refused TLS: ${answer}`);
    const tls = tlsConnect({ socket: sock, servername: db.hostname, ca, rejectUnauthorized: true });
    await race("pg tls handshake", new Promise<void>((resolve, reject) => {
      tls.once("secureConnect", () => resolve());
      tls.once("error", reject);
    }));
    stage("pg tls ok (arkham's minted leaf)");
    tls.write(pgStartup({ user: db.username, database: db.pathname.slice(1) }));
    const auth = await pgRead(tls, 9);
    if (auth[0] !== 0x52 || auth.readUInt32BE(5) !== 3) throw new Error(`expected cleartext password auth, got ${auth.toString("latin1")}`);
    stage("pg cleartext auth requested");
    tls.write(pgFrame(0x70, Buffer.from(`${db.password}\0`, "utf8")));
    const ok = await pgRead(tls, 9);
    if (ok[0] !== 0x52 || ok.readUInt32BE(5) !== 0) throw new Error(`auth rejected: ${ok.toString("latin1")}`);
    stage("pg authenticated - the fake was swapped for the real");
    tls.write(pgFrame(0x51, Buffer.from("SELECT 'ok'\0", "utf8")));
    const result = await race("pg query reply", new Promise<Buffer>((resolve, reject) => {
      let buf = Buffer.alloc(0);
      const onData = (chunk: Buffer) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.includes(0x5a)) {
          tls.off("data", onData);
          resolve(buf);
        }
      };
      tls.on("data", onData);
      tls.once("error", reject);
    }));
    tls.destroy();
    sock.destroy();
    stage("pg query ok");
    return result.includes(Buffer.from("ok"));
  });
} else {
  stage("pg scenario skipped: no DATABASE_URL");
}

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

// 8. SSH: a plain openssh binary, the decoy identity, and nothing else.
// Options inline (no config file): strict checking with accept-new and a
// writable known_hosts of its own, so the first connection records arkham's
// host key — ssh's mechanism is the allowlist, arkham adds no pins.
const SSH_DST = process.env.SSH_DST ?? "";
const SSH_IDENTITY = process.env.SSH_IDENTITY ?? "/certs/ssh/decoy";
const SSH_KNOWN_HOSTS = "/tmp/known_hosts";
const sshCommand = [
  "ssh",
  "-i",
  SSH_IDENTITY,
  "-o",
  "IdentitiesOnly=yes",
  "-o",
  "StrictHostKeyChecking=accept-new",
  "-o",
  `UserKnownHostsFile=${SSH_KNOWN_HOSTS}`,
  "-o",
  "GlobalKnownHostsFile=/dev/null",
  "-o",
  "BatchMode=yes",
  "-o",
  "ConnectTimeout=5",
  `agent@${SSH_DST}`,
  "echo",
  "ssh-ok",
];
if (SSH_DST) {
  await retry("ssh", "ssh decoy in, real key out", async () => {
    const proc = Bun.spawn(sshCommand, { stdout: "pipe", stderr: "pipe" });
    const out = await new Response(proc.stdout).text();
    const err = await new Response(proc.stderr).text();
    const code = await proc.exited;
    stage(`ssh reply: ${JSON.stringify({ code, out, err })}`);
    if (code !== 0 || out.trim() !== "ssh-ok") {
      return false;
    }
    // Debian hashes known_hosts entries, so assert on the recorded key
    // blob: it must be arkham's host key, proving the client verified and
    // stored it via its own accept-new — never a pre-mounted pin.
    const [known, arkhamHost] = await Promise.all([
      readFile(SSH_KNOWN_HOSTS, "utf8"),
      readFile("/certs/ssh/arkham_host.pub", "utf8"),
    ]);
    return known.includes(arkhamHost.trim().split(" ")[1] ?? "");
  });
} else {
  stage("ssh scenario skipped: no SSH_DST (bwrap)");
}

// Bun's Redis client speaks RESP3. On connect it sends
// `HELLO 3 AUTH <user> <password>`, using the user `default` when the URL
// omits one. Commands issued together are pipelined. The proxy swaps the
// fake password; this process only holds the decoy URL.
function openRedis(raw: string, tls: boolean): RedisClient {
  const options: {
    connectionTimeout: number;
    autoReconnect: boolean;
    maxRetries: number;
    enableOfflineQueue: boolean;
    tls?: {
      ca: ReturnType<typeof Bun.file>;
      rejectUnauthorized: boolean;
    };
  } = {
    connectionTimeout: ATTEMPT_TIMEOUT_MS,
    autoReconnect: false,
    maxRetries: 0,
    enableOfflineQueue: false,
  };
  if (tls) {
    options.tls = {
      ca: Bun.file(`${CERT_DIR}/ca.crt`),
      rejectUnauthorized: true,
    };
  }
  return new RedisClient(raw, options);
}

function passwordOnly(raw: string): string {
  const url = new URL(raw);
  url.username = "";
  return url.toString();
}

function errorText(err: unknown): string {
  if (err instanceof Error) {
    const code = "code" in err ? String((err as { code?: unknown }).code ?? "") : "";
    return `${code} ${err.message}`.trim();
  }
  return String(err);
}

// A bad password on the URL makes Bun's HELLO fail, and that rejection is
// reported as a closed connection. AUTH after a successful handshake is a
// normal command error, which carries Redis's WRONGPASS text.
async function redisFailureText(raw: string, tls: boolean): Promise<string> {
  const url = new URL(raw);
  const client = openRedis(raw, tls);
  const messages: string[] = [];
  client.onclose = (err) => {
    messages.push(errorText(err));
  };
  try {
    await client.connect();
    const reply = await client.send("AUTH", [url.username, "wrong_password"]);
    messages.push(JSON.stringify(reply));
  } catch (err) {
    messages.push(errorText(err));
  } finally {
    client.close();
  }
  return messages.join(" ");
}

function helloHasProto3(reply: unknown): boolean {
  if (reply === null || typeof reply !== "object" || Array.isArray(reply)) {
    return false;
  }
  const proto = (reply as { proto?: unknown }).proto;
  return proto === 3 || proto === "3";
}

// 9 and 10. Redis plaintext and TLS. requirepass uses a password-only URL
// (HELLO AUTH default). ACL uses the username in the URL. A later HELLO,
// pipelined PING and SET, and a rejected password follow the same client.
async function redisScenarios(kind: "plaintext" | "tls", raw: string) {
  const tls = kind === "tls";
  const scheme = tls ? "rediss" : "redis";
  const requirepass =
    kind === "plaintext" ? "redis plaintext requirepass auth swaps password" : "redis tls requirepass auth over arkham MITM";
  const hello = kind === "plaintext" ? "redis plaintext HELLO 3 AUTH via send" : "redis tls HELLO 3 AUTH via send";
  const pipelined = kind === "plaintext" ? "redis plaintext pipelined PING and SET" : "redis tls pipelined PING and SET";
  const key = kind === "tls" ? "tls_test_key" : "test_key";
  const value = kind === "tls" ? "tls_test_value" : "test_value";

  await retry(scheme, requirepass, async () => {
    const client = openRedis(passwordOnly(raw), tls);
    try {
      await client.connect();
      const pong = await client.ping();
      stage(`redis ${kind} PING reply: ${pong}`);
      return pong === "PONG";
    } finally {
      client.close();
    }
  });

  await retry(scheme, `redis ${kind} ACL username+password`, async () => {
    const client = openRedis(raw, tls);
    try {
      await client.connect();
      const result = await client.set(key, value);
      stage(`redis ${kind} SET reply: ${result}`);
      return result === "OK";
    } finally {
      client.close();
    }
  });

  await retry(scheme, hello, async () => {
    const redisUrl = new URL(raw);
    const client = openRedis(raw, tls);
    try {
      await client.connect();
      const reply = await client.send("HELLO", ["3", "AUTH", redisUrl.username, redisUrl.password]);
      const text = JSON.stringify(reply);
      stage(`redis ${kind} HELLO 3 reply: ${text}`);
      return helloHasProto3(reply) && !text.includes("arkham_real_redis_pass");
    } finally {
      client.close();
    }
  });

  await retry(scheme, pipelined, async () => {
    const client = openRedis(raw, tls);
    try {
      await client.connect();
      const [pong, stored] = await Promise.all([client.ping(), client.set("pipeline_key", "pipeline_value")]);
      stage(`redis ${kind} pipelined results: ${JSON.stringify([pong, stored])}`);
      return pong === "PONG" && stored === "OK";
    } finally {
      client.close();
    }
  });

  await retry(scheme, `redis ${kind} WRONGPASS without real secret leak`, async () => {
    const errMsg = await redisFailureText(raw, tls);
    stage(`redis ${kind} WRONGPASS error: ${errMsg}`);
    return errMsg.includes("WRONGPASS") && !errMsg.includes("arkham_real_redis_pass");
  });
}

if (REDIS_URL) {
  await redisScenarios("plaintext", REDIS_URL);
} else {
  stage("redis plaintext scenarios skipped: no REDIS_URL");
}

if (REDIS_TLS_URL) {
  await redisScenarios("tls", REDIS_TLS_URL);
} else {
  stage("redis tls scenarios skipped: no REDIS_TLS_URL");
}

function runSmtp(mode: string, url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("python3", ["/srv/smtp.py", mode, url], { env: process.env });
    let out = "";
    child.stdout.on("data", (chunk: Buffer) => {
      out += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      out += chunk.toString();
    });
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolve(out);
      else reject(new Error(out || `smtp.py exited ${code}`));
    });
  });
}

if (SMTP_URL) {
  await retry("smtp", "smtp STARTTLS AUTH PLAIN and LOGIN swap the password", async () => {
    const out = await runSmtp("smtp", SMTP_URL);
    stage(out.trim());
    const direct = await readFile("/out/smtp-direct.txt", "utf8").catch(() => "");
    return direct.includes("decoy refused 587") && direct.includes("decoy refused 465") && out.includes("before-starttls refused") && out.includes("plain ok") && out.includes("login ok") && out.includes("login mechanism ok") && out.includes("wrong refused") && out.includes("smtp ok") && !out.includes("arkham_real_smtp_pass");
  });
} else {
  stage("smtp scenarios skipped: no SMTP_URL");
}

if (SMTPS_URL) {
  await retry("smtps", "smtps implicit TLS AUTH PLAIN swaps the password", async () => {
    const out = await runSmtp("smtps", SMTPS_URL);
    stage(out.trim());
    const authed = out.includes("plain ok") && out.includes("wrong refused") && out.includes("smtps ok") && !out.includes("arkham_real_smtp_pass");
    if (!SMTP_URL) {
      return authed;
    }
    const direct = await readFile("/out/smtp-direct.txt", "utf8").catch(() => "");
    return authed && direct.includes("decoy refused 465");
  });
} else {
  stage("smtps scenarios skipped: no SMTPS_URL");
}

function ldapCode(err: unknown): number | undefined {
  if (err && typeof err === "object" && "code" in err && typeof err.code === "number") {
    return err.code;
  }
  return undefined;
}

function ldapParts(raw: string) {
  const url = new URL(raw);
  return {
    dn: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
    host: url.hostname,
    port: url.port,
  };
}

function ldapPlain(raw: string) {
  const parts = ldapParts(raw);
  return new Client({
    url: `ldap://${parts.host}:${parts.port}`,
    timeout: 4000,
    connectTimeout: 4000,
  });
}

function ldapTls(raw: string) {
  const parts = ldapParts(raw);
  return new Client({
    url: `ldaps://${parts.host}:${parts.port}`,
    timeout: 4000,
    connectTimeout: 4000,
    tlsOptions: { ca, rejectUnauthorized: true, servername: parts.host },
  });
}

async function closeLdap(client: Client) {
  try {
    await client.unbind();
  } catch {
    // A refused bind may already have dropped the socket.
  }
}

if (LDAP_URL) {
  const parts = ldapParts(LDAP_URL);
  // nsslapd-require-secure-binds answers every cleartext bind with 13, decoy
  // or real, so this check cannot see whether the password was swapped. The
  // in-process test compares those bytes. The directory's rejection of the
  // decoy itself (result 49) is an LDAPS bind inside the ldap container.
  await retry("ldap", "ldap plain simple bind before starttls is refused", async () => {
    const client = ldapPlain(LDAP_URL);
    try {
      await client.bind(parts.dn, parts.password);
      return false;
    } catch (err) {
      const text = String(err);
      stage(`ldap plain bind error: ${text}`);
      return ldapCode(err) === 13 && !text.includes(LDAP_REAL);
    } finally {
      await closeLdap(client);
    }
  });

  await retry("ldap", "ldap starttls simple bind swaps the decoy password", async () => {
    const client = ldapPlain(LDAP_URL);
    try {
      await client.startTLS({ ca, rejectUnauthorized: true, servername: parts.host });
      await client.bind(parts.dn, parts.password);
      return true;
    } finally {
      await closeLdap(client);
    }
  });

  // The refused bind leaves the socket up. StartTLS on that same connection
  // has to upgrade, then the decoy bind has to be accepted.
  await retry("ldap", "ldap bind then starttls then bind swaps the decoy password", async () => {
    const client = ldapPlain(LDAP_URL);
    try {
      try {
        await client.bind(parts.dn, parts.password);
        return false;
      } catch (err) {
        const text = String(err);
        stage(`ldap pre-starttls bind error: ${text}`);
        if (ldapCode(err) !== 13 || text.includes(LDAP_REAL)) {
          return false;
        }
      }
      await client.startTLS({ ca, rejectUnauthorized: true, servername: parts.host });
      await client.bind(parts.dn, parts.password);
      return true;
    } finally {
      await closeLdap(client);
    }
  });

  // A search is a message boundary that is not StartTLS. The upgrade still
  // has to happen before the decoy bind.
  await retry("ldap", "ldap search then starttls then bind swaps the decoy password", async () => {
    const client = ldapPlain(LDAP_URL);
    try {
      await client.search("", { scope: "base", filter: "(objectClass=*)" });
      await client.startTLS({ ca, rejectUnauthorized: true, servername: parts.host });
      await client.bind(parts.dn, parts.password);
      return true;
    } catch (err) {
      stage(`ldap search then starttls error: ${String(err)}`);
      return false;
    } finally {
      await closeLdap(client);
    }
  });

  await retry("ldap", "ldap starttls non-decoy password is not swapped", async () => {
    const client = ldapPlain(LDAP_URL);
    try {
      await client.startTLS({ ca, rejectUnauthorized: true, servername: parts.host });
      await client.bind(parts.dn, "not-the-ldap-decoy");
      return false;
    } catch (err) {
      const text = String(err);
      stage(`ldap unswapped bind error: ${text}`);
      return ldapCode(err) === 49 && !text.includes(LDAP_REAL);
    } finally {
      await closeLdap(client);
    }
  });
} else {
  stage("ldap scenarios skipped: no LDAP_URL");
}

if (LDAP_TLS_URL) {
  const parts = ldapParts(LDAP_TLS_URL);
  await retry("ldaps", "ldaps simple bind swaps the decoy password", async () => {
    const client = ldapTls(LDAP_TLS_URL);
    try {
      await client.bind(parts.dn, parts.password);
      return true;
    } finally {
      await closeLdap(client);
    }
  });

  await retry("ldaps", "ldaps non-decoy password is not swapped", async () => {
    const client = ldapTls(LDAP_TLS_URL);
    try {
      await client.bind(parts.dn, "not-the-ldap-decoy");
      return false;
    } catch (err) {
      const text = String(err);
      stage(`ldaps unswapped bind error: ${text}`);
      return ldapCode(err) === 49 && !text.includes(LDAP_REAL);
    } finally {
      await closeLdap(client);
    }
  });
} else {
  stage("ldaps scenarios skipped: no LDAP_TLS_URL");
}

function natsParts(raw: string) {
  const url = new URL(raw);
  return {
    user: decodeURIComponent(url.username),
    pass: decodeURIComponent(url.password),
    server: `${url.hostname}:${url.port}`,
  };
}

function openNats(raw: string, pass: string): Promise<NatsConnection> {
  const parts = natsParts(raw);
  return race("nats connect", natsConnect({
    servers: parts.server,
    user: parts.user,
    pass,
    tls: { ca: ca.toString() },
    timeout: 4000,
    reconnect: false,
  }));
}

if (NATS_URL) {
  const parts = natsParts(NATS_URL);
  const sc = StringCodec();
  // The server's only account holds the real password, so a session that
  // authenticates with the decoy proves the swap. The payload carries the
  // decoy and must arrive unchanged: payloads are never rewritten.
  await once("nats", "nats tls CONNECT swaps the decoy password; publish and receive", async () => {
    const nc = await openNats(NATS_URL, parts.pass);
    try {
      const subject = "arkham.demo";
      const body = `payload keeps ${parts.pass}`;
      const sub = nc.subscribe(subject, { max: 1 });
      nc.publish(subject, sc.encode(body));
      const got = await race("nats message", (async () => {
        for await (const msg of sub) return sc.decode(msg.data);
        return "";
      })());
      stage(`nats received: ${got}`);
      return got === body;
    } finally {
      await nc.close();
    }
  });

  await once("nats", "nats non-decoy password is not swapped", async () => {
    try {
      const nc = await openNats(NATS_URL, "not-the-nats-decoy");
      await nc.close();
      return false;
    } catch (err) {
      const text = String(err);
      stage(`nats unswapped CONNECT error: ${text}`);
      return text.includes("Authorization Violation") && !text.includes(NATS_REAL);
    }
  });
} else {
  stage("nats scenarios skipped: no NATS_URL");
}

function amqpParts(raw: string) {
  const url = new URL(raw);
  return {
    host: url.hostname,
    port: Number(url.port),
    user: decodeURIComponent(url.username),
    password: decodeURIComponent(url.password),
  };
}

function amqpWithPassword(raw: string, password: string): string {
  const url = new URL(raw);
  url.password = encodeURIComponent(password);
  return url.toString();
}

async function amqp091RoundTrip(raw: string): Promise<boolean> {
  const conn = await race("amqp 0-9-1 open", amqplib.connect(raw, { ca: [ca], timeout: ATTEMPT_TIMEOUT_MS }));
  try {
    const channel = await race("amqp 0-9-1 channel", conn.createConfirmChannel());
    const { queue } = await race("amqp 0-9-1 declare", channel.assertQueue("", { exclusive: true }));
    channel.sendToQueue(queue, Buffer.from("amqp-ok"));
    await race("amqp 0-9-1 confirm", channel.waitForConfirms());
    const message = await race("amqp 0-9-1 get", channel.get(queue, { noAck: true }));
    stage(`amqp 0-9-1 get: ${message === false ? "empty" : message.content.toString()}`);
    return message !== false && message.content.toString() === "amqp-ok";
  } finally {
    await race("amqp 0-9-1 close", conn.close()).catch(() => undefined);
  }
}

async function amqp091Refusal(raw: string): Promise<string> {
  try {
    const conn = await race("amqp 0-9-1 open", amqplib.connect(raw, { ca: [ca], timeout: ATTEMPT_TIMEOUT_MS }));
    await race("amqp 0-9-1 close", conn.close()).catch(() => undefined);
    return "opened";
  } catch (err) {
    return String(err);
  }
}

function amqp10Open(raw: string, tls: boolean, password: string): Promise<string> {
  const parts = amqpParts(raw);
  return race("amqp 1.0 open", new Promise<string>((resolve) => {
    const connection = rhea.create_container().connect({
      host: parts.host,
      port: parts.port,
      transport: tls ? "tls" : "tcp",
      ca: [ca],
      servername: parts.host,
      username: parts.user,
      password,
      hostname: "vhost:/",
      reconnect: false,
    });
    connection.on("connection_open", () => {
      connection.close();
      resolve("open");
    });
    connection.on("connection_error", (context) => {
      const error = context.error as { condition?: string; description?: string } | undefined;
      resolve(`error ${error?.condition ?? ""} ${error?.description ?? ""}`.trim());
    });
    connection.on("disconnected", (context) => {
      resolve(`disconnected ${String(context.error ?? "")}`.trim());
    });
  }));
}

function amqpBody(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === "string") return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  return Buffer.from(String(value));
}

// One byte short of the real password, then a breaker, repeated. The full
// password never appears, so a held prefix is released when the message ends.
// Shifts cover every alignment against a stable frame size. Forty copies are
// longer than the lowered max, so the broker splits the body.
function amqpSplitBodies(): Buffer[] {
  const unit = Buffer.concat([Buffer.from(AMQP_REAL.slice(0, -1)), Buffer.from([0x71])]);
  const repeated = Buffer.concat(Array.from({ length: 40 }, () => unit));
  return Array.from({ length: AMQP_REAL.length }, (_, shift) => Buffer.concat([
    Buffer.alloc(shift, 0x71),
    repeated,
  ]));
}

async function amqp10Split(raw: string): Promise<boolean> {
  const parts = amqpParts(raw);
  const sent = amqpSplitBodies();
  const prefix = AMQP_REAL.slice(0, -1);
  if (sent.some((body) => body.includes(AMQP_REAL) || !body.includes(prefix))) return false;
  const queue = `arkham-split-${randomBytes(4).toString("hex")}`;
  const address = `/queues/${queue}`;
  const setup = await race("amqp 1.0 split declare", amqplib.connect(raw, { timeout: ATTEMPT_TIMEOUT_MS }));
  try {
    const channel = await race("amqp 1.0 split queue", setup.createChannel());
    await race("amqp 1.0 split assert", channel.assertQueue(queue, { durable: false, autoDelete: true }));
  } finally {
    await setup.close();
  }
  return race("amqp 1.0 split", new Promise<boolean>((resolve) => {
    let settled = false;
    const finish = (ok: boolean) => {
      if (settled) return;
      settled = true;
      connection.close();
      resolve(ok);
    };
    const connection = rhea.create_container().connect({
      host: parts.host,
      port: parts.port,
      transport: "tcp",
      username: parts.user,
      password: parts.password,
      hostname: "vhost:/",
      max_frame_size: 1024,
      reconnect: false,
    });
    const got = new Map<number, Buffer>();
    let sentOnce = false;
    connection.on("connection_open", () => {
      connection.open_receiver({ source: { address }, credit_window: 64 });
      connection.open_sender({ target: { address } });
    });
    connection.on("sendable", (context) => {
      if (sentOnce || context.sender === undefined) return;
      sentOnce = true;
      sent.forEach((body, shift) => {
        context.sender.send({
          body,
          message_id: `arkham-${String(shift).padStart(2, "0")}`,
        });
      });
    });
    connection.on("message", (context) => {
      const id = context.message?.message_id;
      const index = typeof id === "string" ? Number(id.slice("arkham-".length)) : Number.NaN;
      if (!Number.isInteger(index) || index < 0 || index >= sent.length) {
        stage(`amqp 1.0 split unexpected id: ${String(id)}`);
        finish(false);
        return;
      }
      got.set(index, amqpBody(context.message?.body));
      if (got.size < sent.length) return;
      const match = sent.every((body, at) => got.get(at)?.equals(body) ?? false);
      const leaked = [...got.values()].some((body) => body.includes(AMQP_REAL));
      stage(`amqp 1.0 split: messages=${got.size} match=${match} leaked=${leaked}`);
      finish(match && !leaked);
    });
    connection.on("connection_error", (context) => {
      const error = context.error as { condition?: string; description?: string } | undefined;
      stage(`amqp 1.0 split error: ${error?.condition ?? ""} ${error?.description ?? ""}`.trim());
      finish(false);
    });
    connection.on("disconnected", (context) => {
      if (settled) return;
      stage(`amqp 1.0 split disconnected: ${String(context.error ?? "")}`.trim());
      finish(false);
    });
  }));
}

async function amqpScenarios(scheme: "amqp" | "amqps", raw: string) {
  const tls = scheme === "amqps";
  const parts = amqpParts(raw);

  await retry(scheme, `${scheme} 0-9-1 PLAIN swaps the decoy user and password`, () => amqp091RoundTrip(raw));

  await retry(scheme, `${scheme} 1.0 SASL PLAIN swaps the decoy user and password`, async () => {
    const outcome = await amqp10Open(raw, tls, parts.password);
    stage(`${scheme} 1.0 outcome: ${outcome}`);
    return outcome === "open";
  });

  await retry(scheme, `${scheme} 0-9-1 non-decoy password is not swapped`, async () => {
    const text = await amqp091Refusal(amqpWithPassword(raw, "not-the-amqp-decoy"));
    stage(`${scheme} 0-9-1 refusal: ${text}`);
    return /ACCESS.REFUSED/.test(text) && !text.includes(AMQP_REAL);
  });

  await retry(scheme, `${scheme} 1.0 non-decoy password is not swapped`, async () => {
    const outcome = await amqp10Open(raw, tls, "not-the-amqp-decoy");
    stage(`${scheme} 1.0 refusal: ${outcome}`);
    return outcome.includes("amqp:unauthorized-access") && !outcome.includes(AMQP_REAL);
  });

  if (!tls) {
    await retry(scheme, `${scheme} 1.0 split delivery returns the exact body`, () => amqp10Split(raw));
  }
}

function spliceFatal(why: string): never {
  console.error(`FAIL grantless amqp 0-9-1 splices untouched: ${why}`);
  process.exit(1);
}

function proxyDialed(port: number, localPort: number): boolean {
  const proc = spawnSync("ss", ["-Htn", "state", "established", `( dport = :${port} )`], { encoding: "utf8" });
  if (proc.status !== 0 || typeof proc.stdout !== "string") return false;
  for (const raw of proc.stdout.split("\n")) {
    const local = raw.trim().split(/\s+/)[2];
    if (local === undefined || local === "") continue;
    const colon = local.lastIndexOf(":");
    if (colon < 0) continue;
    const parsed = Number(local.slice(colon + 1));
    if (parsed > 0 && parsed !== localPort) return true;
  }
  return false;
}

async function witnessFile(root: string, names: readonly string[], deadline: number): Promise<{ name: string; text: string }> {
  while (Date.now() < deadline) {
    for (const name of names) {
      try {
        return { name, text: await readFile(join(root, name), "utf8") };
      } catch (err) {
        const missing = typeof err === "object" && err !== null && "code" in err && err.code === "ENOENT";
        if (!missing) throw err;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("amqp splice witness silent");
}

async function grantlessSplice(raw: string): Promise<boolean> {
  const port = Number(process.env.AMQP_SPLICE_PORT);
  const dir = process.env.AMQP_SPLICE_DIR ?? "";
  if (!port || dir === "") spliceFatal("amqp splice port or dir is missing");
  const url = new URL(raw);
  url.port = String(port);
  const root = join(dir, randomBytes(8).toString("hex"));
  await mkdir(root);
  const sent: Buffer[] = [];
  const received: Buffer[] = [];
  let captured = false;
  let pending = 0;
  let finished = false;
  let resolveDone: () => void = () => undefined;
  const closed = new Promise<void>((resolve) => {
    resolveDone = resolve;
  });
  const settle = () => {
    if (finished && pending === 0) resolveDone();
  };
  // amqplib exposes no socket, so the bytes it sends are only visible here.
  const original = Socket.prototype.connect;
  Socket.prototype.connect = function (this: Socket, ...args: unknown[]) {
    this.prependListener("connect", () => {
      if (this.remotePort !== port) return;
      pending += 1;
      const guestPort = this.localPort ?? 0;
      const sample = () => {
        if (captured || guestPort <= 0) return;
        captured = proxyDialed(port, guestPort);
      };
      const write = this.write;
      this.write = function (this: Socket, data: string | Uint8Array, ...rest: unknown[]) {
        const copy = typeof data === "string"
          ? Buffer.from(data, typeof rest[0] === "string" ? rest[0] as BufferEncoding : "utf8")
          : Buffer.from(data);
        sent.push(copy);
        sample();
        return write.call(this, data as never, ...(rest as []));
      } as typeof this.write;
      this.on("data", (chunk: Buffer | string) => {
        received.push(Buffer.from(chunk));
        sample();
      });
      this.on("close", () => {
        pending -= 1;
        settle();
      });
    });
    return original.apply(this, args as never);
  } as typeof Socket.prototype.connect;
  const deadline = Math.min(Date.now() + SCENARIO_BUDGET_MS, DEADLINE);
  try {
    const armed = await witnessFile(root, ["error", "listening"], deadline).catch((err: unknown) => {
      spliceFatal(err instanceof Error ? err.message : String(err));
    });
    if (armed.name === "error") spliceFatal(armed.text.trim());
    let refusal = "login succeeded";
    try {
      const conn = await amqplib.connect(url.toString(), { timeout: ATTEMPT_TIMEOUT_MS });
      await conn.close();
    } catch (err) {
      refusal = err instanceof Error ? err.message : String(err);
    }
    finished = true;
    settle();
    await closed;
    await writeFile(join(root, "closed"), "");
    const result = await witnessFile(root, ["error", "empty", "done"], deadline).catch((err: unknown) => {
      spliceFatal(err instanceof Error ? err.message : String(err));
    });
    if (result.name === "error") spliceFatal(result.text.trim());
    const guestSent = Buffer.concat(sent);
    const guestRecv = Buffer.concat(received);
    if (result.name === "empty") {
      throw new Error(`amqp splice empty capture sent=${guestSent.length} recv=${guestRecv.length} ${result.text.trim()}`);
    }
    const names = result.text.trim().split("\n");
    if (names.length !== 2 || names[0] === "" || names[1] === "") spliceFatal("amqp splice flow pairing failed");
    const toBroker = await readFile(join(root, names[0]));
    const toClient = await readFile(join(root, names[1]));
    if (guestSent.length === 0 || guestRecv.length === 0 || toBroker.length === 0 || toClient.length === 0) {
      throw new Error(`amqp splice empty capture sent=${guestSent.length} recv=${guestRecv.length} toBroker=${toBroker.length} toClient=${toClient.length}`);
    }
    if (!guestSent.equals(toBroker) || !guestRecv.equals(toClient)) {
      spliceFatal(`splice mismatch sent=${guestSent.length} toBroker=${toBroker.length} recv=${guestRecv.length} toClient=${toClient.length}`);
    }
    if (!refusal.includes("403") || !/ACCESS.REFUSED/.test(refusal)) spliceFatal(`refusal: ${refusal}`);
    const pass = Buffer.from(amqpParts(raw).password);
    const plainAt = toBroker.indexOf("PLAIN");
    if (plainAt < 0 || toBroker.indexOf(pass) < plainAt || toBroker.includes(AMQP_REAL)) spliceFatal("Start-Ok decoy was rewritten");
    if (!captured) spliceFatal(`proxy did not capture ${port}`);
    return true;
  } finally {
    Socket.prototype.connect = original;
    await rm(root, { recursive: true, force: true });
  }
}

if (AMQP_URL) {
  await amqpScenarios("amqp", AMQP_URL);
  await retry("", "grantless amqp 0-9-1 splices untouched", () => grantlessSplice(AMQP_URL));
} else {
  stage("amqp scenarios skipped: no AMQP_URL");
}

if (AMQP_TLS_URL) {
  await amqpScenarios("amqps", AMQP_TLS_URL);
} else {
  stage("amqps scenarios skipped: no AMQP_TLS_URL");
}

function natsServer(raw: string): string {
  const url = new URL(raw);
  return `${url.hostname}:${url.port}`;
}

// nkeys.js fromSeed rejects a trailing newline. nsc seed files and the
// mounted decoy both end with one.
function nkeySeed(bytes: Uint8Array): Uint8Array {
  return new TextEncoder().encode(new TextDecoder().decode(bytes).trim());
}

function openNatsAuth(raw: string, authenticator: Authenticator): Promise<NatsConnection> {
  return race("nats connect", natsConnect({
    servers: natsServer(raw),
    authenticator,
    tls: { ca: ca.toString() },
    timeout: 4000,
    reconnect: false,
  }));
}

type NatsContextFile = {
  url: string;
  nkey?: string;
  creds?: string;
};

function natsConfigDir(): string {
  return join(homedir(), ".config", "nats");
}

async function installNatsContext(name: string, body: NatsContextFile): Promise<void> {
  const root = natsConfigDir();
  await mkdir(join(root, "context"), { recursive: true });
  await writeFile(join(root, "context", `${name}.json`), `${JSON.stringify(body)}\n`);
  await writeFile(join(root, "context.txt"), `${name}\n`);
}

async function selectedNatsContext(): Promise<NatsContextFile> {
  const root = natsConfigDir();
  const name = (await readFile(join(root, "context.txt"), "utf8")).trim();
  const raw = await readFile(join(root, "context", `${name}.json`), "utf8");
  return JSON.parse(raw) as NatsContextFile;
}

function credsFile(jwt: string, seed: string): Uint8Array {
  const text = [
    "-----BEGIN NATS USER JWT-----",
    jwt,
    "------END NATS USER JWT------",
    "",
    "-----BEGIN USER NKEY SEED-----",
    seed,
    "------END USER NKEY SEED------",
    "",
  ].join("\n");
  return new TextEncoder().encode(text);
}

async function natsRoundTrip(raw: string, authenticator: Authenticator, label: string): Promise<boolean> {
  const sc = StringCodec();
  const nc = await openNatsAuth(raw, authenticator);
  try {
    const subject = `arkham.${label}`;
    const body = `payload keeps ${label}`;
    const sub = nc.subscribe(subject, { max: 1 });
    nc.publish(subject, sc.encode(body));
    const got = await race("nats message", (async () => {
      for await (const msg of sub) return sc.decode(msg.data);
      return "";
    })());
    stage(`nats ${label} received: ${got}`);
    return got === body;
  } finally {
    await nc.close();
  }
}

function natsRejected(err: unknown): boolean {
  const text = String(err);
  stage(`nats unswapped authenticator error: ${text}`);
  return text.includes("Authorization Violation") && !text.includes(NATS_REAL);
}

if (process.env.NATS_DISCOVERED === "1") {
  await once("nats", "nats host ~/.config/nats discovery swaps the mounted decoy nkey; publish and receive", async () => {
    const ctx = await selectedNatsContext();
    if (!ctx.nkey || !ctx.url) return false;
    const nkeyPath = ctx.nkey.startsWith("~/") ? join(homedir(), ctx.nkey.slice(2)) : ctx.nkey;
    const fromFile = nkeySeed(await readFile(nkeyPath));
    if (NATS_NKEY_URL) {
      const fnoxFake = decodeURIComponent(new URL(NATS_NKEY_URL).password);
      if (new TextDecoder().decode(fromFile).includes(fnoxFake)) return false;
    }
    return natsRoundTrip(ctx.url, nkeyAuthenticator(fromFile), "discovered");
  });
}

if (NATS_NKEY_URL) {
  if (!NATS_NKEY_FOREIGN) {
    console.error("nats nkey material is incomplete");
    process.exit(1);
  }
  const seed = decodeURIComponent(new URL(NATS_NKEY_URL).password);
  const nkeyPath = join(natsConfigDir(), "nkey.nk");
  await mkdir(natsConfigDir(), { recursive: true });
  await writeFile(nkeyPath, seed);
  const nkeyServer = new URL(NATS_NKEY_URL);
  await installNatsContext("nkey", {
    url: `${nkeyServer.protocol}//${nkeyServer.host}`,
    nkey: nkeyPath,
  });
  await once("nats", "nats tls CONNECT swaps the decoy nkey read from ~/.config/nats; publish and receive", async () => {
    const ctx = await selectedNatsContext();
    if (!ctx.nkey || !ctx.url) return false;
    const fromFile = nkeySeed(await readFile(ctx.nkey));
    return natsRoundTrip(ctx.url, nkeyAuthenticator(fromFile), "nkey");
  });

  await once("nats", "nats non-decoy nkey is not swapped", async () => {
    try {
      const nc = await openNatsAuth(NATS_NKEY_URL, nkeyAuthenticator(new TextEncoder().encode(NATS_NKEY_FOREIGN)));
      await nc.close();
      return false;
    } catch (err) {
      if (String(err).includes("timed out")) throw err;
      return natsRejected(err);
    }
  });
} else {
  stage("nats nkey scenarios skipped: no NATS_NKEY_URL");
}

if (NATS_JWT_URL) {
  if (!NATS_JWT_FOREIGN_SEED || !NATS_JWT_FOREIGN_JWT) {
    console.error("nats user jwt material is incomplete");
    process.exit(1);
  }
  const jwtUrl = new URL(NATS_JWT_URL);
  const password = decodeURIComponent(jwtUrl.password);
  const split = password.indexOf(":");
  const fakeSeed = split < 0 ? "" : password.slice(0, split);
  const fakeJwt = split < 0 ? "" : password.slice(split + 1);
  const credsPath = join(natsConfigDir(), "user.creds");
  await mkdir(natsConfigDir(), { recursive: true });
  await writeFile(credsPath, credsFile(fakeJwt, fakeSeed));
  const jwtServer = new URL(NATS_JWT_URL);
  await installNatsContext("jwt", {
    url: `${jwtServer.protocol}//${jwtServer.host}`,
    creds: credsPath,
  });
  await once("nats", "nats tls CONNECT swaps the decoy user jwt read from ~/.config/nats; publish and receive", async () => {
    const ctx = await selectedNatsContext();
    if (!ctx.creds || !ctx.url) return false;
    const fromFile = await readFile(ctx.creds);
    return natsRoundTrip(ctx.url, credsAuthenticator(fromFile), "jwt");
  });

  await once("nats", "nats non-decoy user jwt is not swapped", async () => {
    try {
      const nc = await openNatsAuth(
        NATS_JWT_URL,
        credsAuthenticator(credsFile(NATS_JWT_FOREIGN_JWT, NATS_JWT_FOREIGN_SEED)),
      );
      await nc.close();
      return false;
    } catch (err) {
      if (String(err).includes("timed out")) throw err;
      return natsRejected(err);
    }
  });
} else {
  stage("nats user jwt scenarios skipped: no NATS_JWT_URL");
}

const coveredPath = process.env.ARKHAM_COVERED ?? "";
if (coveredPath) {
  await writeFile(coveredPath, `${JSON.stringify([...covered].sort())}\n`);
}
console.log("all scenarios passed");
process.exit(0);
