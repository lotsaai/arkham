// postgres scenarios through arkham's transparent capture. The client holds only decoys.
import { connect } from "node:net";
import { Client as PgClient } from "pg";
import { ATTEMPT_TIMEOUT_MS, race, stage, retry, ca, errorText, finish } from "./lib.ts";

const PG_URL = process.env.DATABASE_URL ?? ""; // the fake connection string
// pg parses sslmode out of the connection string and replaces any ssl
// object passed next to it. The guest URL says sslmode=require, which
// becomes an empty ssl object and drops the demo CA. Delete that
// parameter so hostname verification against the demo CA stays on.
// The server accepts only the real password, so a decoy login means
// arkham authenticated upstream with it.
if (PG_URL) {
  function openPg(raw: string): PgClient {
    const url = new URL(raw);
    url.searchParams.delete("sslmode");
    return new PgClient({
      connectionString: url.toString(),
      ssl: { ca, rejectUnauthorized: true },
      connectionTimeoutMillis: ATTEMPT_TIMEOUT_MS,
    });
  }

  await retry("postgres", "postgres mitm swaps the password for a real server", async () => {
    const client = openPg(PG_URL);
    try {
      await race("pg connect", client.connect());
      const result = await race("pg query", client.query("SELECT 'ok' AS ok"));
      const value = result.rows[0]?.ok;
      stage(`pg query reply: ${JSON.stringify(value)}`);
      return value === "ok";
    } finally {
      await client.end();
    }
  });

  await retry("postgres", "postgres non-decoy password is not swapped", async () => {
    const url = new URL(PG_URL);
    url.password = "not-the-pg-decoy";
    const client = openPg(url.toString());
    try {
      await race("pg connect", client.connect());
      return false;
    } catch (err) {
      const text = errorText(err);
      stage(`pg unswapped error: ${text}`);
      const refused = text.includes("28P01") || text.includes("password authentication failed");
      return refused && !text.includes("arkham_real_password_01");
    } finally {
      await client.end();
    }
  });
} else {
  stage("pg scenario skipped: no DATABASE_URL");
}

await finish();
