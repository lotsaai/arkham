// nats scenarios through arkham's transparent capture. The client holds only decoys.
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";
import { connect as natsConnect, credsAuthenticator, nkeyAuthenticator, type Authenticator, type NatsConnection } from "@nats-io/transport-node";
import { race, stage, once, ca, finish } from "./lib.ts";

const NATS_URL = process.env.NATS_URL ?? "";
const NATS_REAL = "arkham_real_nats_pass";
const NATS_NKEY_URL = process.env.NATS_NKEY_URL ?? "";
const NATS_JWT_URL = process.env.NATS_JWT_URL ?? "";
const NATS_NKEY_FOREIGN = process.env.NATS_NKEY_FOREIGN ?? "";
const NATS_JWT_FOREIGN_SEED = process.env.NATS_JWT_FOREIGN_SEED ?? "";
const NATS_JWT_FOREIGN_JWT = process.env.NATS_JWT_FOREIGN_JWT ?? "";
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
  // The server's only account holds the real password, so a session that
  // authenticates with the decoy proves the swap. The published body carries
  // the decoy, and msg.string() must return that same body. Payloads are
  // never rewritten.
  await once("nats", "nats tls CONNECT swaps the decoy password; publish and receive", async () => {
    const nc = await openNats(NATS_URL, parts.pass);
    try {
      const subject = "arkham.demo";
      const body = `payload keeps ${parts.pass}`;
      const sub = nc.subscribe(subject, { max: 1 });
      nc.publish(subject, body);
      const got = await race("nats message", (async () => {
        for await (const msg of sub) return msg.string();
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
  const nc = await openNatsAuth(raw, authenticator);
  try {
    const subject = `arkham.${label}`;
    const body = `payload keeps ${label}`;
    const sub = nc.subscribe(subject, { max: 1 });
    nc.publish(subject, body);
    const got = await race("nats message", (async () => {
      for await (const msg of sub) return msg.string();
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

await finish();
