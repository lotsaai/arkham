// Shared helpers for the compose e2e clients. Each protocol has its own
// client file. Hard bounds everywhere: 5s per network await, 20s per
// scenario, and 90s for the whole run. The first failure ends the run.
import { readFile, writeFile } from "node:fs/promises";
import { Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";

export const FAKE = process.env.ARKHAM_FAKE ?? "";
export const OIDC_FAKE_SECRET = process.env.OIDC_FAKE_SECRET ?? "";
export const CERT_DIR = process.env.CERT_DIR ?? "/certs";
export const ATTEMPT_TIMEOUT_MS = 5000;
export const SCENARIO_BUDGET_MS = 20000;
const TOTAL_BUDGET_MS = 90000;
export const DEADLINE = Date.now() + TOTAL_BUDGET_MS;

if (!FAKE || !OIDC_FAKE_SECRET) {
  console.error("ARKHAM_FAKE or OIDC_FAKE_SECRET not set");
  process.exit(1);
}

function outOfTime() {
  return Date.now() > DEADLINE;
}

export function race<T>(what: string, p: Promise<T>): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`${what}: timed out after ${ATTEMPT_TIMEOUT_MS}ms`)), ATTEMPT_TIMEOUT_MS).unref?.();
    }),
  ]);
}

export function stage(what: string) {
  process.stderr.write(`[${new Date().toISOString().slice(17, 23)}] ${what}\n`);
}

export async function tlsTo(host: string, port: number, ca: Buffer): Promise<TLSSocket> {
  stage(`tls ${host}:${port} connecting`);
  const tls = tlsConnect({ host, port, servername: host, ca, rejectUnauthorized: true });
  await race(`tls ${host}:${port} handshake`, new Promise<void>((resolve, reject) => {
    tls.once("secureConnect", () => resolve());
    tls.once("error", reject);
  }));
  stage(`tls ${host}:${port} handshake ok`);
  return tls;
}

export function exchange(sock: Socket | TLSSocket, payload: string): Promise<string> {
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

const covered = new Set<string>();

export async function once(scheme: string, what: string, fn: () => Promise<boolean>) {
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

export async function retry(scheme: string, what: string, fn: () => Promise<boolean>) {
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

export const ca = await readFile(`${CERT_DIR}/ca.crt`);

export function errorText(err: unknown): string {
  if (err instanceof Error) {
    const code = "code" in err ? String((err as { code?: unknown }).code ?? "") : "";
    return `${code} ${err.message}`.trim();
  }
  return String(err);
}

// Record the schemes the passing scenarios covered, then exit clean.
export async function finish(): Promise<never> {
  const coveredPath = process.env.ARKHAM_COVERED ?? "";
  if (coveredPath) {
    await writeFile(coveredPath, `${JSON.stringify([...covered].sort())}\n`);
  }
  console.log("all scenarios passed");
  process.exit(0);
}
