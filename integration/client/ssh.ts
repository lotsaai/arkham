// ssh scenarios through arkham's transparent capture. The client holds only decoys.
import { readFile } from "node:fs/promises";
import { stage, retry, finish } from "./lib.ts";
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

await finish();
