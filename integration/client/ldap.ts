// ldap scenarios through arkham's transparent capture. The client holds only decoys.
import { readFile } from "node:fs/promises";
import { Client } from "ldapts";
import { CERT_DIR, stage, retry, ca, finish } from "./lib.ts";

const LDAP_URL = process.env.LDAP_URL ?? "";
const LDAP_TLS_URL = process.env.LDAP_TLS_URL ?? "";
const LDAP_UPSTREAM_TLS_URL = process.env.LDAP_UPSTREAM_TLS_URL ?? "";
const LDAP_MTLS_URL = process.env.LDAP_MTLS_URL ?? "";
const LDAP_REAL = "arkham_real_ldap_pass_01";
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

  // ldapts sends StartTLS on the open socket with no already-upgraded guard.
  // The second call is an extended operation over the protected session.
  await retry("ldap", "ldap second starttls on a tls session is operations error", async () => {
    const client = ldapPlain(LDAP_URL);
    try {
      await client.startTLS({ ca, rejectUnauthorized: true, servername: parts.host });
      await client.bind(parts.dn, parts.password);
      try {
        await client.startTLS({ ca, rejectUnauthorized: true, servername: parts.host });
        return false;
      } catch (err) {
        const text = String(err);
        stage(`ldap second starttls error: ${text}`);
        if (ldapCode(err) !== 1 || text.includes(LDAP_REAL)) {
          return false;
        }
      }
      await client.bind(parts.dn, parts.password);
      return true;
    } catch (err) {
      stage(`ldap second starttls setup error: ${String(err)}`);
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

if (LDAP_UPSTREAM_TLS_URL) {
  const parts = ldapParts(LDAP_UPSTREAM_TLS_URL);
  // The real string is ldaps://, so the cleartext bind is already swapped.
  // A cleartext upstream would answer that bind with confidentialityRequired.
  await retry("ldap", "ldap bind then starttls against an already tls upstream swaps the decoy", async () => {
    const client = ldapPlain(LDAP_UPSTREAM_TLS_URL);
    try {
      await client.bind(parts.dn, parts.password);
      await client.startTLS({ ca, rejectUnauthorized: true, servername: parts.host });
      await client.bind(parts.dn, parts.password);
      return true;
    } catch (err) {
      stage(`ldap already-tls upstream error: ${String(err)}`);
      return false;
    } finally {
      await closeLdap(client);
    }
  });
} else {
  stage("ldap upstream-tls scenarios skipped: no LDAP_UPSTREAM_TLS_URL");
}

if (LDAP_MTLS_URL) {
  const parts = ldapParts(LDAP_MTLS_URL);
  const guestCert = await readFile(`${CERT_DIR}/ldap-guest.crt`);
  const guestKey = await readFile(`${CERT_DIR}/ldap-guest.key`);
  const protectedTls = { ca, rejectUnauthorized: true, servername: parts.host, cert: guestCert, key: guestKey };
  await retry("ldap", "ldap bind then starttls with a client certificate swaps the decoy", async () => {
    const client = ldapPlain(LDAP_MTLS_URL);
    try {
      try {
        await client.bind(parts.dn, parts.password);
        return false;
      } catch (err) {
        const text = String(err);
        stage(`ldap mtls pre-starttls bind error: ${text}`);
        if (ldapCode(err) !== 13 || text.includes(LDAP_REAL)) {
          return false;
        }
      }
      await client.startTLS(protectedTls);
      await client.bind(parts.dn, parts.password);
      return true;
    } catch (err) {
      stage(`ldap mtls starttls error: ${String(err)}`);
      return false;
    } finally {
      await closeLdap(client);
    }
  });

  await retry("ldap", "ldap bind then starttls without a client certificate is refused", async () => {
    const client = ldapPlain(LDAP_MTLS_URL);
    try {
      try {
        await client.bind(parts.dn, parts.password);
        return false;
      } catch (err) {
        const text = String(err);
        if (ldapCode(err) !== 13 || text.includes(LDAP_REAL)) {
          stage(`ldap mtls certless bind error: ${text}`);
          return false;
        }
      }
      // A required client certificate can close the socket after `startTLS`
      // has already resolved. The refusal is a failed protected bind.
      try {
        await client.startTLS({ ca, rejectUnauthorized: true, servername: parts.host });
      } catch (err) {
        const text = String(err);
        stage(`ldap mtls certless handshake error: ${text}`);
        return !text.includes(LDAP_REAL);
      }
      try {
        await client.bind(parts.dn, parts.password);
        stage("ldap mtls certless protected bind succeeded");
        return false;
      } catch (err) {
        const text = String(err);
        stage(`ldap mtls certless protected bind error: ${text}`);
        return !text.includes(LDAP_REAL);
      }
    } finally {
      await closeLdap(client);
    }
  });
} else {
  stage("ldap mtls scenarios skipped: no LDAP_MTLS_URL");
}

await finish();
