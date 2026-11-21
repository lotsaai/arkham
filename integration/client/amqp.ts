// amqp scenarios through arkham's transparent capture. The client holds only decoys.
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { connect, Socket } from "node:net";
import { join } from "node:path";
import amqplib from "amqplib";
import rhea from "rhea";
import { ATTEMPT_TIMEOUT_MS, SCENARIO_BUDGET_MS, DEADLINE, race, stage, once, retry, ca, finish } from "./lib.ts";

const AMQP_URL = process.env.AMQP_URL ?? "";
const AMQP_TLS_URL = process.env.AMQP_TLS_URL ?? "";
const AMQP_REAL = "arkham_real_amqp_pass_longer_01";
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
    // RabbitMQ 4.3 refuses a transient non-exclusive queue. Durable survives
    // this connection so the rhea link can attach to /queues/:queue.
    await race("amqp 1.0 split assert", channel.assertQueue(queue, { durable: true }));
  } finally {
    await race("amqp 1.0 split close", setup.close()).catch(() => undefined);
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
  console.error(`FAIL grantless amqp splice: ${why}`);
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

async function grantlessSplice(raw: string, version: "0-9-1" | "1.0"): Promise<boolean> {
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
  // Match the requested destination before eBPF redirects the socket to loopback.
  const original = Socket.prototype.connect;
  Socket.prototype.connect = function(this: Socket, ...args: unknown[]) {
    const options = Array.isArray(args[0]) ? args[0][0] : args[0];
    if (typeof options !== "object" || options === null || !("port" in options) || !("host" in options)
      || options.port !== port || options.host !== url.hostname) return original.apply(this, args as never);
    this.prependListener("connect", () => {
      pending += 1;
      const guestPort = this.localPort ?? 0;
      const sample = () => {
        if (captured || guestPort <= 0) return;
        captured = proxyDialed(port, guestPort);
      };
      const write = this.write;
      this.write = function(this: Socket, data: string | Uint8Array, ...rest: unknown[]) {
        const copy = typeof data === "string"
          ? Buffer.from(data, typeof rest[0] === "string" ? rest[0] as BufferEncoding : "utf8")
          : Buffer.from(data);
        const last = rest.at(-1);
        const callback = typeof last === "function" ? rest.pop() as (error?: Error | null) => void : undefined;
        rest.push((error?: Error | null) => {
          if (!error) sent.push(copy);
          callback?.(error);
        });
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
    let refusal: string;
    if (version === "1.0") {
      refusal = await amqp10Open(url.toString(), false, amqpParts(raw).password);
    } else {
      try {
        const conn = await amqplib.connect(url.toString(), { timeout: ATTEMPT_TIMEOUT_MS });
        await conn.close();
        refusal = "login succeeded";
      } catch (err) {
        refusal = err instanceof Error ? err.message : String(err);
      }
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
    if (version === "1.0" ? !refusal.includes("amqp:unauthorized-access") : !refusal.includes("403") || !/ACCESS.REFUSED/.test(refusal)) {
      spliceFatal(`refusal: ${refusal}`);
    }
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
  await once("", "grantless amqp 0-9-1 splices untouched", () => grantlessSplice(AMQP_URL, "0-9-1"));
  await once("", "grantless amqp 1.0 splices untouched", () => grantlessSplice(AMQP_URL, "1.0"));
} else {
  stage("amqp scenarios skipped: no AMQP_URL");
}

if (AMQP_TLS_URL) {
  await amqpScenarios("amqps", AMQP_TLS_URL);
} else {
  stage("amqps scenarios skipped: no AMQP_TLS_URL");
}

await finish();
