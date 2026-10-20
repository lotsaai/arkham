//! CA management + per-domain leaf certificate generation.

use std::fmt::{Debug, Formatter, Result as FmtResult};
use std::fs;
use std::io::{ErrorKind, Write as _};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::str;
use std::sync::Arc;
use std::thread;

use rama::crypto::pem::PemEncode as _;
use rama::tls::boring::core::pkey::{PKey, Private};
use rama::tls::boring::core::x509::X509;
use rcgen::{
  BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

use crate::error::Error;

/// Leaf validity for generated per-domain certificates.
const LEAF_VALIDITY_HOURS: u64 = 24;
/// A certificate authority for signing per-domain certificates.
pub struct CertAuthority {
  issuer: Issuer<'static, KeyPair>,
  cert_der: CertificateDer<'static>,
  /// PEM-encoded CA certificate (for client installation).
  cert_pem: String,
}

impl Debug for CertAuthority {
  /// Prints only what is safe to log: the private key is never rendered, and
  /// the certificate is summarized rather than dumped.
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    f.debug_struct("CertAuthority")
      .field("cert_pem_bytes", &self.cert_pem.len())
      .field("cert_der_bytes", &self.cert_der.len())
      .finish_non_exhaustive()
  }
}

impl CertAuthority {
  /// Generate a new self-signed CA.
  ///
  /// # Errors
  ///
  /// Returns an error when key generation or self-signing fails.
  pub fn generate() -> Result<Self, Error> {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "arkham CA");
    dn.push(DnType::OrganizationName, "arkham");
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let key_pair = KeyPair::generate().map_err(|source| Error::Keygen { source })?;
    let cert = params.self_signed(&key_pair).map_err(|source| Error::SelfSign { source })?;

    let cert_pem = cert.pem();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let issuer = Issuer::new(params, key_pair);

    Ok(Self {
      issuer,
      cert_der,
      cert_pem,
    })
  }

  /// Load a CA from PEM-encoded certificate and private key bytes.
  ///
  /// The original PEM bytes are preserved for `cert_pem()` so the identity
  /// served to clients matches the persisted file exactly.
  ///
  /// # Errors
  ///
  /// Returns an error when either PEM is not valid UTF-8, the key is not a
  /// parseable PKCS#8 key pair, or the certificate is not a parseable CA.
  pub fn load(cert_pem_bytes: &[u8], key_pem_bytes: &[u8]) -> Result<Self, Error> {
    let cert_pem_str = str::from_utf8(cert_pem_bytes).map_err(|source| Error::InvalidCertPem { source })?;
    let key_pem_str = str::from_utf8(key_pem_bytes).map_err(|source| Error::InvalidKeyPem { source })?;

    let key_pair = KeyPair::from_pem(key_pem_str).map_err(|source| Error::ParseKey { source })?;
    let issuer = Issuer::from_ca_cert_pem(cert_pem_str, key_pair).map_err(|source| Error::ParseCert { source })?;

    let original_der = {
      CertificateDer::from_pem_slice(cert_pem_str.as_bytes())
        .map(|cert| cert.to_vec())
        .map_err(|source| Error::ParsePem { source })?
    };

    Ok(Self {
      issuer,
      cert_der: CertificateDer::from(original_der),
      cert_pem: cert_pem_str.to_string(),
    })
  }

  /// Get the CA certificate as PEM bytes (for client installation).
  #[must_use]
  pub fn cert_pem(&self) -> Vec<u8> {
    self.cert_pem.as_bytes().to_vec()
  }

  /// Get the CA private key as PEM bytes (for persistence).
  #[must_use]
  pub fn key_pem(&self) -> Vec<u8> {
    self.issuer.key().serialize_pem().as_bytes().to_vec()
  }

  /// DER-encoded CA certificate.
  #[must_use]
  pub fn cert_der(&self) -> &CertificateDer<'static> {
    &self.cert_der
  }

  /// Generate a leaf certificate for `domain` signed by this CA.
  ///
  /// # Errors
  ///
  /// Returns an error when the domain is not a valid SAN or signing fails.
  pub fn generate_domain_cert(&self, domain: &str) -> Result<DomainCert, Error> {
    generate_domain_cert(domain, self)
  }

  /// Boring CA pair for the rama MITM issuer: cert DER plus the PKCS8 key
  /// bytes this CA already holds, converted to boring types.
  ///
  /// # Errors
  ///
  /// Returns an error when the cert DER or the PKCS8 key bytes fail to parse
  /// as boring types.
  pub fn boring_pair(&self) -> Result<(X509, PKey<Private>), Error> {
    let crt = X509::from_der(self.cert_der.as_ref()).map_err(|source| Error::BoringCert { source: source.into() })?;
    let key =
      PKey::private_key_from_pkcs8(&self.issuer.key().serialize_der()).map_err(|source| Error::BoringKey { source: source.into() })?;
    Ok((crt, key))
  }
}

/// Load the CA from `path`, or generate + persist one (creating parent dirs).
/// File format is the cert PEM followed by the PKCS#8 key PEM, and both are
/// also written beside it as `<stem>.crt` and `<stem>.key`.
/// `create_new` elects a single winner across racing processes; losers load
/// the winner with backoff because the winner's `write_all` may not have
/// finished when `AlreadyExists` surfaces. A persistently unparseable file
/// (crash mid-write) stays a hard error: silently minting a fresh CA would
/// invalidate every installed client trust anchor.
///
/// # Errors
///
/// Returns an error when the existing file cannot be read or parsed, when the
/// parent directory cannot be created, or when no process wins the
/// generate-and-persist race.
pub fn load_or_generate(path: &Path) -> Result<CertAuthority, Error> {
  let ca = if path.exists() {
    load_ca_file(path)?
  } else {
    generate_and_persist(path)?
  };
  sync_split_pems(path, &ca);
  Ok(ca)
}

/// Generate a CA and persist it, electing one winner across racing processes.
fn generate_and_persist(path: &Path) -> Result<CertAuthority, Error> {
  if let Some(parent) = path.parent() {
    fs::create_dir_all(parent).map_err(Error::Io)?;
  }
  let ca = CertAuthority::generate()?;
  let mut contents = ca.cert_pem();
  contents.extend_from_slice(&ca.key_pem());
  match persist_ca_0600(path, &contents) {
    Ok(()) => Ok(ca),
    // Raced with another process creating it: load the winner.
    Err(err) if err.kind() == ErrorKind::AlreadyExists => load_ca_file_with_retry(path),
    Err(err) => Err(Error::Io(err)),
  }
}

/// Keep `<stem>.crt` and `<stem>.key` beside the CA file, so a deployment can
/// hand the certificate to a workload without handing over the key. The
/// combined PEM stays the file arkham reads, and it stays authoritative: an
/// unchanged split file is left alone and a write failure is a warning rather
/// than a startup error, so a read-only mount still serves.
fn sync_split_pems(path: &Path, ca: &CertAuthority) {
  for (target, contents, mode) in [
    (path.with_extension("crt"), ca.cert_pem(), 0o644),
    (path.with_extension("key"), ca.key_pem(), 0o600),
  ] {
    if fs::read(&target).is_ok_and(|existing| existing == contents) {
      continue;
    }
    if let Err(err) = write_with_mode(&target, &contents, mode) {
      tracing::warn!(path = %target.display(), %err, "failed to write the split CA file");
    }
  }
}

/// Write `contents` to `target`, forcing `mode` so a umask cannot leave the
/// private key world readable.
fn write_with_mode(target: &Path, contents: &[u8], mode: u32) -> std::io::Result<()> {
  let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).open(target)?;
  file.write_all(contents)?;
  file.sync_all()?;
  set_mode(target, mode)
}

#[cfg(unix)]
fn set_mode(target: &Path, mode: u32) -> std::io::Result<()> {
  fs::set_permissions(target, fs::Permissions::from_mode(mode))
}

fn load_ca_file(path: &Path) -> Result<CertAuthority, Error> {
  warn_on_loose_ca_perms(path);
  let text = fs::read_to_string(path)?;
  let key_start = text
    .find("-----BEGIN PRIVATE KEY-----")
    .ok_or_else(|| Error::NoKeyBlock { path: path.to_path_buf() })?;
  CertAuthority::load(&text.as_bytes()[..key_start], &text.as_bytes()[key_start..])
}

/// Warn when the CA file is group/other readable: the private key block
/// lives in the same file, so loose permissions are a full MITM hazard.
#[cfg(unix)]
fn warn_on_loose_ca_perms(path: &Path) {
  let Ok(meta) = fs::metadata(path) else {
    return;
  };
  if meta.permissions().mode() & 0o077 != 0 {
    tracing::warn!(path = %path.display(), "CA file readable by group/other; expected 0600");
  }
}

/// Load the winner's CA file, retrying while the winner is still writing.
/// Truncated reads (missing key block, PEM parse failure) retry for ~2s;
/// the last error surfaces when the file stays unparseable.
fn load_ca_file_with_retry(path: &Path) -> Result<CertAuthority, Error> {
  let mut last = load_ca_file(path).err();
  for _ in 0..20 {
    thread::sleep(std::time::Duration::from_millis(100));
    match load_ca_file(path) {
      Ok(ca) => return Ok(ca),
      Err(err) => last = Some(err),
    }
  }
  Err(last.unwrap_or_else(|| Error::NeverReadable { path: path.to_path_buf() }))
}

#[cfg(unix)]
fn persist_ca_0600(path: &Path, contents: &[u8]) -> std::io::Result<()> {
  let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
  file.write_all(contents)?;
  file.sync_all()?;
  // Best-effort dir sync so the directory entry survives a crash.
  if let Some(parent) = path.parent()
    && let Ok(dir) = fs::File::open(parent)
  {
    let _ = dir.sync_all();
  }
  Ok(())
}

/// A generated certificate for a specific domain, with a cached
/// `ServerConfig` to avoid rebuilding it per connection.
pub struct DomainCert {
  /// Expiry time for the generated leaf certificate.
  pub expires_at: OffsetDateTime,
  /// Pre-built `ServerConfig` for this domain (avoids per-connection rebuild).
  pub server_config: Arc<ServerConfig>,
}

impl Debug for DomainCert {
  /// The pre-built `ServerConfig` holds the leaf private key and is not
  /// rendered; only the expiry is.
  fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
    f.debug_struct("DomainCert")
      .field("expires_at", &self.expires_at)
      .finish_non_exhaustive()
  }
}

/// Generate a certificate for `domain` (SAN = SNI) signed by the given CA.
///
/// # Errors
///
/// Returns an error when `domain` is not a valid SAN, when leaf key
/// generation or signing fails, or when rustls rejects the resulting chain.
pub fn generate_domain_cert(domain: &str, ca: &CertAuthority) -> Result<DomainCert, Error> {
  let (chain, key, expires_at) = signed_leaf(ca, domain, ExtendedKeyUsagePurpose::ServerAuth)?;
  let server_config = ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .map_err(|source| Error::ServerConfig { source })?;
  Ok(DomainCert {
    expires_at,
    server_config: Arc::new(server_config),
  })
}

/// Generate a client identity signed by the CA: the certificate chain (leaf
/// plus CA) and its PKCS8 key, for the proxy's upstream mTLS leg.
///
/// # Errors
///
/// Returns an error when key generation or signing fails.
pub fn generate_client_pair(ca: &CertAuthority, domain: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Error> {
  let (chain, key, _) = signed_leaf(ca, domain, ExtendedKeyUsagePurpose::ClientAuth)?;
  Ok((chain, key))
}

/// Load the guest identity `name` from `dir` (`<name>.pem` plus
/// `<name>.key`), or mint a CA-signed client pair into those files when
/// either is missing. Returns the two paths. An existing pair is never
/// overwritten: minting only ever happens when a file is absent.
///
/// # Errors
///
/// Returns an error when the pair cannot be generated or written.
pub fn load_or_generate_client_pair(ca: &CertAuthority, dir: &Path, name: &str) -> Result<(PathBuf, PathBuf), Error> {
  let cert = dir.join(format!("{name}.pem"));
  let key = dir.join(format!("{name}.key"));
  if cert.is_file() && key.is_file() {
    return Ok((cert, key));
  }
  let (chain, private) = generate_client_pair(ca, name)?;
  fs::create_dir_all(dir).map_err(|source| Error::CreateGuestDir {
    dir: dir.to_path_buf(),
    source,
  })?;
  let mut cert_pem = String::new();
  for leaf in &chain {
    cert_pem.push_str(&leaf.to_pem());
  }
  fs::write(&cert, cert_pem).map_err(|source| Error::WriteGuestCert {
    path: cert.clone(),
    source,
  })?;
  let mut key_file = fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    .mode(0o600)
    .open(&key)
    .map_err(|source| Error::OpenGuestKey { path: key.clone(), source })?;
  key_file
    .write_all(private.to_pem().as_bytes())
    .map_err(|source| Error::WriteGuestKey { path: key.clone(), source })?;
  Ok((cert, key))
}

/// Generate a server leaf signed by the CA: the certificate chain (leaf plus
/// CA) and its PKCS8 key, for callers that build their own server config.
///
/// # Errors
///
/// Returns an error when key generation or signing fails.
pub fn generate_domain_pair(ca: &CertAuthority, domain: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Error> {
  let (chain, key, _) = signed_leaf(ca, domain, ExtendedKeyUsagePurpose::ServerAuth)?;
  Ok((chain, key))
}

/// Leaf generation shared by the pair helpers: one key, one CA signature, the
/// named key usage, the chain with the CA appended, and the expiry the
/// callers cache by.
fn signed_leaf(
  ca: &CertAuthority,
  domain: &str,
  usage: ExtendedKeyUsagePurpose,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>, OffsetDateTime), Error> {
  let now = OffsetDateTime::now_utc();
  let mut params = CertificateParams::new(vec![domain.to_string()]).map_err(|source| Error::BadSni { source })?;
  let mut dn = DistinguishedName::new();
  dn.push(DnType::CommonName, domain);
  params.distinguished_name = dn;
  params.is_ca = IsCa::ExplicitNoCa;
  params.use_authority_key_identifier_extension = true;
  params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
  params.extended_key_usages = vec![usage];
  // Backdate not_before by 2 seconds for clock skew.
  params.not_before = now - Duration::seconds(2);
  params.not_after = now + Duration::hours(LEAF_VALIDITY_HOURS.cast_signed());
  let expires_at = params.not_after;
  let key_pair = KeyPair::generate().map_err(|source| Error::LeafKeygen { source })?;
  let cert_der = params
    .signed_by(&key_pair, &ca.issuer)
    .map_err(|source| Error::LeafSign { source })?;
  Ok((
    vec![CertificateDer::from(cert_der.der().to_vec()), ca.cert_der.clone()],
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
    expires_at,
  ))
}

/// Install the aws-lc-rs crypto provider as the process default. Idempotent;
/// required before building any rustls config.
pub fn install_crypto_provider() {
  let _ = aws_lc_rs::default_provider().install_default();
}

#[cfg(test)]
mod tests {
  use super::*;
  use rustls::pki_types::ServerName;
  use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection, StreamOwned};
  use std::io::Read as _;
  use std::net::{TcpListener, TcpStream};
  use tempfile::tempdir;

  #[test]
  fn ca_roundtrips_through_file_byte_exact() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sub").join("ca.pem");
    let ca = load_or_generate(&path).unwrap();
    let before = fs::read(&path).unwrap();
    let reloaded = load_or_generate(&path).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    assert_eq!(reloaded.cert_der, ca.cert_der);
  }

  #[test]
  fn leaf_covers_ip_san() {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let cert = generate_domain_cert("127.0.0.1", &ca).unwrap();
    assert!(cert.expires_at > OffsetDateTime::now_utc());
  }

  #[test]
  fn split_pems_hold_one_half_each() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    let ca = load_or_generate(&path).unwrap();

    let crt = fs::read_to_string(dir.path().join("ca.crt")).unwrap();
    let key = fs::read_to_string(dir.path().join("ca.key")).unwrap();
    assert!(crt.contains("BEGIN CERTIFICATE"));
    assert!(!crt.contains("PRIVATE KEY"), "the certificate file carried the key");
    assert!(key.contains("PRIVATE KEY"));
    assert!(!key.contains("CERTIFICATE"), "the key file carried the certificate");

    // The combined file is still the certificate followed by the key.
    let pem = fs::read_to_string(&path).unwrap();
    assert!(pem.starts_with(&crt));
    assert!(pem.contains(&key));
    assert_eq!(crt, String::from_utf8(ca.cert_pem()).unwrap());
  }

  #[cfg(unix)]
  #[test]
  fn split_key_is_owner_only() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    load_or_generate(&path).unwrap();
    let mode = fs::metadata(dir.path().join("ca.key")).unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "key mode was {mode:o}");
  }

  #[test]
  fn a_deleted_split_file_is_rewritten_from_the_pem() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("ca.pem");
    load_or_generate(&path).unwrap();
    let before = fs::read(dir.path().join("ca.crt")).unwrap();
    fs::remove_file(dir.path().join("ca.crt")).unwrap();

    load_or_generate(&path).unwrap();
    assert_eq!(fs::read(dir.path().join("ca.crt")).unwrap(), before);
  }

  /// Leaves minted for IP-look identities carry an IP SAN (rcgen's
  /// `CertificateParams::new` IP-detects), so a hostname-verifying client
  /// completes against them — and the same client refuses a DNS leaf. Pins
  /// the transparent-capture shape, where the identity is the destination
  /// address.
  #[test]
  fn ip_identities_mint_leaves_a_verifying_client_accepts() {
    install_crypto_provider();
    let ca = CertAuthority::generate().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let mint = |name: &str| {
      let (chain, key) = generate_domain_pair(&ca, name).unwrap();
      Arc::new(ServerConfig::builder().with_no_client_auth().with_single_cert(chain, key).unwrap())
    };
    let leaves = [mint("127.0.0.1"), mint("localhost")];

    let server = thread::spawn(move || {
      for config in leaves {
        let Ok((stream, _)) = listener.accept() else { return };
        let Ok(conn) = ServerConnection::new(config) else { return };
        let mut tls = StreamOwned::new(conn, stream);
        let _ = tls.write_all(b"ok");
        let _ = tls.flush();
      }
    });

    let mut roots = RootCertStore::empty();
    roots.add(ca.cert_der().clone()).unwrap();
    let handshake = |label: &str| {
      let stream = TcpStream::connect(addr).unwrap();
      let conn = ClientConnection::new(
        Arc::new(ClientConfig::builder().with_root_certificates(roots.clone()).with_no_client_auth()),
        ServerName::IpAddress(addr.ip().into()),
      )
      .map_err(|err| format!("{label}: connect {err}"))?;
      let mut tls = StreamOwned::new(conn, stream);
      tls.write_all(b"x").map_err(|err| format!("{label}: write {err}"))?;
      let mut buf = [0u8; 2];
      tls.read_exact(&mut buf).map_err(|err| format!("{label}: read {err}"))?;
      Ok::<(), String>(())
    };

    let ip = handshake("the ip leaf");
    let dns = handshake("the dns leaf");
    server.join().unwrap();
    assert!(ip.is_ok(), "the ip leaf failed the IP check: {ip:?}");
    assert!(dns.is_err(), "the dns leaf passed the IP hostname check");
  }
}
