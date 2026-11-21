// redis scenarios through arkham's transparent capture. The client holds only decoys.
import { connect } from "node:net";
import { RedisClient } from "bun";
import { CERT_DIR, ATTEMPT_TIMEOUT_MS, stage, retry, ca, errorText, finish } from "./lib.ts";

const REDIS_URL = process.env.REDIS_URL ?? "";
const REDIS_TLS_URL = process.env.REDIS_TLS_URL ?? "";
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

await finish();
