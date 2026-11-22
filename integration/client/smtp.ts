// smtp scenarios through arkham's transparent capture. The client holds only decoys.
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { stage, retry, finish } from "./lib.ts";

const SMTP_URL = process.env.SMTP_URL ?? "";
const SMTPS_URL = process.env.SMTPS_URL ?? "";
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

await finish();
