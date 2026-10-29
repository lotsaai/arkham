//! Kubeconfig rewrites. [`kube_client::config::Kubeconfig`] is the document:
//! load it, grant every derivable user, and write the decoy back into that
//! same value.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use arkham_config::config::RewriteFormat;
use arkham_config::context::{AmbientProtocol, ContextIdentity, ContextRef, Presented, identities, require_distinct};
use arkham_config::grants::{EndpointScope, HostPat, Scheme};
use arkham_config::{decoy_for_rule, fake_for};
use arkham_pki::ca::{CertAuthority, load_or_generate_client_pair};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use kube_client::config::{AuthInfo, Kubeconfig, KubeconfigError, NamedContext};
use secrecy::{ExposeSecret, SecretString};

use crate::adapt::{GrantFragment, RewriteAdapted, decode, materialize_client_tls, render_decoy, render_fragment};
use crate::error::Error;

/// Map one kubeconfig onto its grant fragment and decoy twin.
///
/// Returns `None` when the document is not a kubeconfig.
///
/// # Errors
///
/// Returns an error when the document does not parse or the current context
/// cannot be derived.
pub(crate) fn adapt(source: &Path, content: &[u8], ca: &CertAuthority, guests_dir: &Path) -> Result<Option<RewriteAdapted>, Error> {
  adapt_sources(&[(source, content)], ca, guests_dir)
}

/// Map a `KUBECONFIG` list, merged in order, onto one grant set and decoy.
///
/// The first file wins a repeated context, cluster, or user name. Returns
/// `None` when the only document is not a kubeconfig.
///
/// # Errors
///
/// Returns an error when a document does not parse, a later file is not a
/// kubeconfig, or the current context cannot be derived.
pub(crate) fn adapt_sources(sources: &[(&Path, &[u8])], ca: &CertAuthority, guests_dir: &Path) -> Result<Option<RewriteAdapted>, Error> {
  let Some((mut config, owners)) = merge_sources(sources)? else {
    return Ok(None);
  };
  let Some(&(file, _)) = sources.first() else {
    return Ok(None);
  };
  let active = active_contexts(&config, &owners, file)?;
  let decoys = user_decoys(&active)?;
  let presented = presented(&active, &decoys)?;
  require_distinct(&presented)?;
  let rendered = render_grants(&active, &decoys, ca, guests_dir)?;
  rewrite_decoy(&mut config, ca, &rendered.guests);
  Ok(Some(RewriteAdapted {
    fragment: rendered.fragment,
    decoy: render_decoy(&config)?,
    materialized: rendered.materialized,
    decoy_files: Vec::new(),
  }))
}

#[derive(Default)]
struct Owners {
  contexts: BTreeMap<String, PathBuf>,
  clusters: BTreeMap<String, PathBuf>,
  users: BTreeMap<String, PathBuf>,
}

struct Raw {
  context: String,
  user: String,
  user_source: PathBuf,
  cluster: String,
  cluster_source: PathBuf,
  server: String,
  host: String,
  port: u16,
  token: Option<String>,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  ca: Option<Vec<u8>>,
}

struct Active {
  user: String,
  server: String,
  host: String,
  port: u16,
  token: Option<String>,
  cert: Option<Vec<u8>>,
  key: Option<Vec<u8>>,
  ca: Option<Vec<u8>>,
  user_id: ContextIdentity,
  cluster_id: ContextIdentity,
}

struct Guest {
  token: String,
  cert: Option<String>,
  key: Option<String>,
}

struct Rendered {
  fragment: String,
  materialized: Vec<(String, Vec<u8>)>,
  guests: BTreeMap<String, Guest>,
}

fn merge_sources(sources: &[(&Path, &[u8])]) -> Result<Option<(Kubeconfig, Owners)>, Error> {
  let mut merged: Option<Kubeconfig> = None;
  let mut owners = Owners::default();
  for &(path, bytes) in sources {
    let doc = read_doc(path, bytes)?;
    if doc.kind.as_deref() != Some("Config") {
      if sources.len() == 1 {
        return Ok(None);
      }
      return Err(invalid(path, "not a kubeconfig"));
    }
    remember(&mut owners.clusters, &doc.clusters, path, |item| &item.name);
    remember(&mut owners.users, &doc.auth_infos, path, |item| &item.name);
    remember(&mut owners.contexts, &doc.contexts, path, |item| &item.name);
    merged = Some(match merged {
      Some(prior) => prior.merge(doc).map_err(|source| kube_error(path, source))?,
      None => doc,
    });
  }
  Ok(merged.map(|config| (config, owners)))
}

fn remember<T>(map: &mut BTreeMap<String, PathBuf>, entries: &[T], path: &Path, name: impl Fn(&T) -> &str) {
  for entry in entries {
    map.entry(name(entry).to_owned()).or_insert_with(|| path.to_path_buf());
  }
}

fn read_doc(path: &Path, bytes: &[u8]) -> Result<Kubeconfig, Error> {
  let text = String::from_utf8_lossy(bytes);
  let mut doc = match Kubeconfig::from_yaml(&text) {
    Ok(doc) => doc,
    Err(source) => return Err(parse_failure(path, &text, source)),
  };
  if let Some(dir) = path.parent() {
    absolutize(&mut doc, dir);
  }
  Ok(doc)
}

fn parse_failure(path: &Path, text: &str, source: KubeconfigError) -> Error {
  match serde_yaml::from_str::<serde_yaml::Mapping>(text) {
    Err(source) => Error::RewriteYaml {
      file: path.to_path_buf(),
      source,
    },
    Ok(_) => kube_error(path, source),
  }
}

fn absolutize(doc: &mut Kubeconfig, dir: &Path) {
  for named in &mut doc.clusters {
    if let Some(cluster) = &mut named.cluster {
      lift(&mut cluster.certificate_authority, dir);
    }
  }
  for named in &mut doc.auth_infos {
    if let Some(auth) = &mut named.auth_info {
      lift(&mut auth.client_certificate, dir);
      lift(&mut auth.client_key, dir);
      lift(&mut auth.token_file, dir);
    }
  }
}

fn lift(slot: &mut Option<String>, dir: &Path) {
  if let Some(abs) = slot.as_deref().and_then(|path| absolute(dir, path)) {
    *slot = Some(abs);
  }
}

fn absolute(dir: &Path, file: &str) -> Option<String> {
  let path = Path::new(file);
  if path.is_relative() {
    dir.join(path).to_str().map(str::to_owned)
  } else {
    None
  }
}

fn active_contexts(config: &Kubeconfig, owners: &Owners, file: &Path) -> Result<Vec<Active>, Error> {
  let current = config
    .current_context
    .as_deref()
    .filter(|name| !name.is_empty())
    .ok_or_else(|| invalid(file, "missing `current-context`"))?;
  if !config.contexts.iter().any(|entry| entry.name == current) {
    return Err(invalid(file, format!("unknown context `{current}`")));
  }
  let mut opened = Vec::new();
  for entry in &config.contexts {
    match open_context(entry, config, owners, file) {
      Ok(item) => opened.push(item),
      Err(err) if entry.name == current => return Err(err),
      Err(err) => tracing::warn!(context = %entry.name, %err, "kube context skipped"),
    }
  }
  let users = identities(&user_refs(&opened))?;
  let clusters = identities(&cluster_refs(&opened))?;
  let mut active = Vec::with_capacity(opened.len());
  for item in opened {
    let user_id = users
      .iter()
      .find(|id| id.name == item.user && id.source == item.user_source)
      .cloned();
    let cluster_id = clusters
      .iter()
      .find(|id| id.name == item.cluster && id.source == item.cluster_source)
      .cloned();
    let (Some(user_id), Some(cluster_id)) = (user_id, cluster_id) else {
      return Err(invalid(file, format!("context `{}` has no identity", item.context)));
    };
    active.push(Active {
      user: item.user,
      server: item.server,
      host: item.host,
      port: item.port,
      token: item.token,
      cert: item.cert,
      key: item.key,
      ca: item.ca,
      user_id,
      cluster_id,
    });
  }
  Ok(active)
}

fn user_refs(opened: &[Raw]) -> Vec<ContextRef<'_>> {
  opened
    .iter()
    .map(|item| ContextRef {
      source: item.user_source.as_path(),
      protocol: AmbientProtocol::KubernetesUser,
      name: item.user.as_str(),
    })
    .collect()
}

fn cluster_refs(opened: &[Raw]) -> Vec<ContextRef<'_>> {
  opened
    .iter()
    .map(|item| ContextRef {
      source: item.cluster_source.as_path(),
      protocol: AmbientProtocol::KubernetesCluster,
      name: item.cluster.as_str(),
    })
    .collect()
}

fn open_context(entry: &NamedContext, config: &Kubeconfig, owners: &Owners, fallback: &Path) -> Result<Raw, Error> {
  let source = owner(&owners.contexts, &entry.name, fallback);
  let Some(spec) = &entry.context else {
    return Err(invalid(source, format!("context `{}` names no `cluster` or no `user`", entry.name)));
  };
  let Some(user_name) = spec.user.as_deref().filter(|user| !user.is_empty()) else {
    return Err(invalid(source, format!("context `{}` names no `cluster` or no `user`", entry.name)));
  };
  if spec.cluster.is_empty() {
    return Err(invalid(source, format!("context `{}` names no `cluster` or no `user`", entry.name)));
  }
  let Some(cluster) = config.clusters.iter().find(|item| item.name == spec.cluster) else {
    return Err(invalid(source, format!("unknown cluster `{}`", spec.cluster)));
  };
  let Some(body) = &cluster.cluster else {
    return Err(invalid(source, format!("cluster `{}` states no `server`", cluster.name)));
  };
  let Some(server) = body.server.as_deref().filter(|server| !server.is_empty()) else {
    return Err(invalid(source, format!("cluster `{}` states no `server`", cluster.name)));
  };
  let scope: EndpointScope = server
    .parse()
    .map_err(|detail| invalid(source, format!("server `{server}` is not an allow entry: {detail}")))?;
  if scope.scheme != Scheme::Https {
    return Err(invalid(
      source,
      format!("server `{server}` is plain HTTP: the API server is TLS-only"),
    ));
  }
  let HostPat::Exact(host) = &scope.host else {
    return Err(invalid(source, format!("server `{server}` is not an exact host")));
  };
  let Some(user) = config.auth_infos.iter().find(|item| item.name == user_name) else {
    return Err(invalid(source, format!("unknown user `{user_name}`")));
  };
  let empty = AuthInfo::default();
  let auth = user.auth_info.as_ref().unwrap_or(&empty);
  let user_source = owner(&owners.users, &user.name, source).to_path_buf();
  let cluster_source = owner(&owners.clusters, &cluster.name, source).to_path_buf();
  let token = bearer(auth, &user_source)?;
  let cert = material(
    &user_source,
    auth.client_certificate_data.as_deref(),
    "client-certificate-data",
    auth.client_certificate.as_deref(),
    "client-certificate",
  )?;
  let key = material(
    &user_source,
    auth.client_key_data.as_ref().map(ExposeSecret::expose_secret),
    "client-key-data",
    auth.client_key.as_deref(),
    "client-key",
  )?;
  if auth.exec.is_some() && token.is_none() && cert.is_none() && key.is_none() {
    return Err(invalid(source, "exec credential plugins are not supported"));
  }
  if cert.is_some() != key.is_some() {
    return Err(invalid(source, format!("user `{}` carries half of the client pair", user.name)));
  }
  if token.is_none() && cert.is_none() {
    let detail = if auth.token.is_none() && auth.auth_provider.is_some() {
      format!("user `{}` uses an auth-provider; that flow is not substituted", user.name)
    } else {
      format!(
        "user `{}` carries neither `token` nor a client pair: nothing to substitute",
        user.name
      )
    };
    return Err(invalid(source, detail));
  }
  let ca = material(
    &cluster_source,
    body.certificate_authority_data.as_deref(),
    "certificate-authority-data",
    body.certificate_authority.as_deref(),
    "certificate-authority",
  )?;
  Ok(Raw {
    context: entry.name.clone(),
    user: user.name.clone(),
    user_source,
    cluster: cluster.name.clone(),
    cluster_source,
    server: server.to_owned(),
    host: host.clone(),
    port: scope.port,
    token,
    cert,
    key,
    ca,
  })
}

fn bearer(auth: &AuthInfo, source: &Path) -> Result<Option<String>, Error> {
  if let Some(token) = &auth.token {
    let text = token.expose_secret();
    if text.is_empty() {
      return Ok(None);
    }
    return Ok(Some(text.to_owned()));
  }
  let Some(file) = &auth.token_file else {
    return Ok(None);
  };
  let bytes = fs::read(file).map_err(|err| invalid(source, format!("cannot read `tokenFile` at `{file}`: {err}")))?;
  let text = String::from_utf8_lossy(&bytes);
  let trimmed = text.trim();
  if trimmed.is_empty() {
    Ok(None)
  } else {
    Ok(Some(trimmed.to_owned()))
  }
}

fn material(
  source: &Path,
  inline: Option<&str>,
  inline_field: &str,
  file: Option<&str>,
  file_field: &str,
) -> Result<Option<Vec<u8>>, Error> {
  if let Some(bytes) = decode(source, RewriteFormat::Kubeconfig, inline, inline_field)? {
    return Ok(Some(bytes));
  }
  let Some(file) = file else {
    return Ok(None);
  };
  fs::read(file)
    .map(Some)
    .map_err(|err| invalid(source, format!("cannot read `{file_field}` at `{file}`: {err}")))
}

fn user_decoys(active: &[Active]) -> Result<BTreeMap<String, String>, Error> {
  let mut decoys = BTreeMap::new();
  for item in active {
    if decoys.contains_key(&item.user_id.label) {
      continue;
    }
    let allow = allow_urls(active.iter().filter(|peer| peer.user_id.label == item.user_id.label));
    let parsed = scopes(&item.user_id.source, &allow)?;
    let (token, _) = decoy_for_rule(&item.user_id.env(), None, &parsed, grant_value(item).len());
    decoys.insert(item.user_id.label.clone(), token);
  }
  Ok(decoys)
}

fn presented<'a>(active: &'a [Active], decoys: &'a BTreeMap<String, String>) -> Result<Vec<Presented<'a>>, Error> {
  let mut out = Vec::with_capacity(active.len());
  for item in active {
    let Some(token) = decoys.get(&item.user_id.label) else {
      return Err(invalid(&item.user_id.source, format!("user `{}` has no decoy", item.user)));
    };
    out.push(Presented {
      identity: &item.user_id,
      host: item.host.as_str(),
      port: item.port,
      decoy: token.as_bytes(),
    });
  }
  Ok(out)
}

fn allow_urls<'a>(peers: impl IntoIterator<Item = &'a Active>) -> Vec<String> {
  let mut allow = Vec::new();
  for peer in peers {
    if allow.iter().any(|url| url == &peer.server) {
      continue;
    }
    allow.push(peer.server.clone());
  }
  allow
}

fn scopes(file: &Path, allow: &[String]) -> Result<Vec<EndpointScope>, Error> {
  allow
    .iter()
    .map(|entry| entry.parse())
    .collect::<Result<Vec<_>, _>>()
    .map_err(|detail| invalid(file, detail))
}

fn grant_value(item: &Active) -> String {
  if let Some(token) = &item.token {
    return token.clone();
  }
  // kubectl sends this user's decoy as a bearer. The proxy substitutes the
  // grant value into that header, and HTTP/2 rejects CR, LF, and NUL there.
  single_line(&String::from_utf8_lossy(item.cert.as_deref().unwrap_or_default()))
}

fn single_line(value: &str) -> String {
  value
    .chars()
    .filter(|ch| {
      let code = u32::from(*ch);
      code == 0x09 || (0x20..0x7f).contains(&code) || code >= 0x80
    })
    .collect::<String>()
    .trim()
    .to_owned()
}

fn render_grants(active: &[Active], decoys: &BTreeMap<String, String>, ca: &CertAuthority, guests_dir: &Path) -> Result<Rendered, Error> {
  let mut rendered = Rendered {
    fragment: String::new(),
    materialized: Vec::new(),
    guests: BTreeMap::new(),
  };
  let mut seen = BTreeSet::new();
  for item in active {
    if !seen.insert(item.user_id.label.clone()) {
      continue;
    }
    let Some(token) = decoys.get(&item.user_id.label) else {
      return Err(invalid(&item.user_id.source, format!("user `{}` has no decoy", item.user)));
    };
    let peers: Vec<&Active> = active.iter().filter(|peer| peer.user_id.label == item.user_id.label).collect();
    grant_one(item, &peers, token, ca, guests_dir, &mut rendered)?;
  }
  Ok(rendered)
}

fn grant_one(
  first: &Active,
  peers: &[&Active],
  decoy_token: &str,
  ca: &CertAuthority,
  guests_dir: &Path,
  rendered: &mut Rendered,
) -> Result<(), Error> {
  let pair = match (&first.cert, &first.key) {
    (Some(cert), Some(key)) => Some((cert.clone(), key.clone())),
    _ => None,
  };
  let (pair_tls, mut materialized) = materialize_client_tls(&first.user_id.label, pair, None);
  let mut allow = Vec::new();
  let mut tls = BTreeMap::new();
  let mut written_ca = BTreeSet::new();
  for peer in peers {
    if allow.iter().any(|url| url == &peer.server) {
      continue;
    }
    let (ca_tls, ca_files) = materialize_client_tls(&peer.cluster_id.label, None, peer.ca.clone());
    let mut entry = pair_tls.clone();
    entry.root_cert = ca_tls.root_cert;
    allow.push(peer.server.clone());
    tls.insert(peer.server.clone(), entry);
    for (name, bytes) in ca_files {
      if written_ca.insert(name.clone()) {
        materialized.push((name, bytes));
      }
    }
  }
  rendered.fragment.push_str(&render_fragment(
    &first.user_id.source,
    &first.user_id.label,
    &GrantFragment {
      env: first.user_id.env(),
      registry: false,
      allow,
      value: Some(grant_value(first)),
      real: None,
      generated: false,
      if_missing: None,
      tls,
      ssh: BTreeMap::new(),
    },
  )?);
  let guest_pair = if pair_tls.client_cert.is_some() {
    let (cert_path, key_path) = load_or_generate_client_pair(ca, guests_dir, &first.user_id.label)?;
    let read = |path: PathBuf| fs::read(&path).map_err(|source| Error::ReadFile { path, source });
    Some((STANDARD.encode(read(cert_path)?), STANDARD.encode(read(key_path)?)))
  } else {
    None
  };
  let (cert, key) = guest_pair.unzip();
  rendered.guests.insert(
    first.user.clone(),
    Guest {
      token: decoy_token.to_owned(),
      cert,
      key,
    },
  );
  rendered.materialized.extend(materialized);
  Ok(())
}

fn rewrite_decoy(config: &mut Kubeconfig, ca: &CertAuthority, guests: &BTreeMap<String, Guest>) {
  let guest_ca = STANDARD.encode(ca.cert_pem());
  for named in &mut config.clusters {
    let Some(cluster) = &mut named.cluster else { continue };
    if cluster.certificate_authority.is_some() || cluster.certificate_authority_data.is_some() {
      cluster.certificate_authority = None;
      cluster.certificate_authority_data = Some(guest_ca.clone());
    }
  }
  for named in &mut config.auth_infos {
    let Some(auth) = &mut named.auth_info else { continue };
    let filler = fake_for(&format!("KUBE_{}", named.name.to_uppercase().replace(['-', '.'], "_")), None);
    let paired = has_pair(auth);
    if let Some(guest) = guests.get(&named.name) {
      auth.token = Some(SecretString::from(guest.token.clone()));
      auth.token_file = None;
      if paired {
        let blank = filler.clone();
        let cert = guest.cert.clone().unwrap_or(blank.clone());
        let key = guest.key.clone().unwrap_or(blank);
        auth.client_certificate = None;
        auth.client_key = None;
        auth.client_certificate_data = Some(cert);
        auth.client_key_data = Some(SecretString::from(key));
      }
    } else if auth.token.is_some() || auth.token_file.is_some() {
      auth.token = Some(SecretString::from(filler.clone()));
      auth.token_file = None;
      if paired {
        auth.client_certificate = None;
        auth.client_key = None;
        auth.client_certificate_data = Some(filler.clone());
        auth.client_key_data = Some(SecretString::from(filler.clone()));
      }
    } else if paired {
      auth.client_certificate = None;
      auth.client_key = None;
      auth.client_certificate_data = Some(filler.clone());
      auth.client_key_data = Some(SecretString::from(filler.clone()));
    }
    if let Some(provider) = &mut auth.auth_provider {
      for value in provider.config.values_mut() {
        value.clone_from(&filler);
      }
    }
    if auth.password.is_some() {
      auth.password = Some(SecretString::from(filler));
    }
    auth.exec = None;
  }
}

fn has_pair(auth: &AuthInfo) -> bool {
  auth.client_certificate.is_some() || auth.client_certificate_data.is_some() || auth.client_key.is_some() || auth.client_key_data.is_some()
}

fn owner<'a>(map: &'a BTreeMap<String, PathBuf>, name: &str, fallback: &'a Path) -> &'a Path {
  map.get(name).map_or(fallback, PathBuf::as_path)
}

fn invalid(file: &Path, detail: impl Into<String>) -> Error {
  Error::RewriteInvalid {
    file: file.to_path_buf(),
    format: RewriteFormat::Kubeconfig,
    detail: detail.into(),
  }
}

fn kube_error(file: &Path, source: KubeconfigError) -> Error {
  Error::Kubeconfig {
    file: file.to_path_buf(),
    source,
  }
}
#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use arkham_config::config::{FileRewrite, RuleCfg};
  use arkham_config::grants::GuestTlsMode;
  use serde::Deserialize;
  use tempfile::tempdir;

  use super::*;
  use crate::adapt::write_state;
  use crate::expand::*;
  use crate::rewrites::*;
  use crate::test_support::{AmbientEnv, KUBE_DOC, WarnCapture};

  fn kube_identity(protocol: AmbientProtocol, name: &str) -> ContextIdentity {
    identities(&[ContextRef {
      source: Path::new(SOURCE),
      protocol,
      name,
    }])
    .expect("identity")
    .into_iter()
    .next()
    .expect("one identity")
  }

  const BEARER_DOC: &str = r"apiVersion: v1
kind: Config
current-context: k3s-local
contexts:
- name: k3s-local
  context: {cluster: k3s, user: admin}
clusters:
- name: k3s
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: admin
  user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
";

  const SOURCE: &str = "/home/ivan/.kube/k3s.yaml";

  fn test_ca() -> CertAuthority {
    CertAuthority::generate().unwrap()
  }

  fn adapt_doc(doc: &str) -> RewriteAdapted {
    let dir = tempfile::tempdir().unwrap();
    adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path())
      .expect("adapt parses")
      .expect("bearer doc is a kubeconfig")
  }

  #[derive(Debug, Deserialize)]
  struct RulesDoc {
    rules: BTreeMap<String, RuleCfg>,
  }

  fn rules_from(fragment: &str) -> BTreeMap<String, RuleCfg> {
    toml_edit::de::from_str::<RulesDoc>(fragment).expect("fragment parses").rules
  }

  #[test]
  fn foreign_content_is_not_a_kubeconfig() {
    let npmrc = "//registry.npmjs.org/:_authToken=secret";
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), npmrc.as_bytes(), &test_ca(), dir.path()).expect_err("plain text fails closed");
    assert!(err.to_string().contains("does not parse as YAML"), "{err}");
  }

  #[test]
  fn label_is_the_user_identity() {
    let user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let adapted = adapt_doc(BEARER_DOC);
    assert!(
      adapted.fragment.contains(&format!("[rules.{}]", user.label)),
      "{}",
      adapted.fragment
    );
    assert!(adapted.fragment.contains(&user.env()), "{}", adapted.fragment);
  }

  #[test]
  fn fragment_holds_the_grant_and_parses_as_a_rule() {
    let adapted = adapt_doc(BEARER_DOC);
    let rules = rules_from(&adapted.fragment);
    let user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let cluster = kube_identity(AmbientProtocol::KubernetesCluster, "k3s");
    let rule = rules.get(&user.label).expect("rule present");
    assert_eq!(rule.env, user.env());
    assert_eq!(rule.allow, vec!["https://10.0.0.1:6443".to_string()]);
    assert_eq!(rule.registry, Some(false));
    assert!(rule.value.is_some(), "bearer token is the inline real value");
    let tls = rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert!(
      tls
        .client_cert
        .as_ref()
        .is_some_and(|path| path.ends_with(format!("{}.client.crt", user.label)))
    );
    assert!(
      tls
        .root_cert
        .as_ref()
        .is_some_and(|path| path.ends_with(format!("{}.ca.crt", cluster.label)))
    );
    assert_eq!(tls.guest_tls_mode, GuestTlsMode::Mtls);
    assert_eq!(adapted.materialized.len(), 3, "pair plus CA materialize beside the fragment");
  }

  #[test]
  fn decoy_keeps_the_server_and_swaps_trust_identity_and_token() {
    let adapted = adapt_doc(BEARER_DOC);
    assert!(adapted.decoy.contains("server: https://10.0.0.1:6443"), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("k3s-token"),
      "no real credential survives: {}",
      adapted.decoy
    );
    assert!(!adapted.decoy.contains("Q0E="), "no real CA survives: {}", adapted.decoy);
    assert!(!adapted.decoy.contains("Q0VSVA=="), "no real pair survives: {}", adapted.decoy);
    assert!(adapted.decoy.contains("token: "), "decoy token present: {}", adapted.decoy);
    assert!(
      adapted.decoy.contains("client-certificate-data: "),
      "guest pair present: {}",
      adapted.decoy
    );
  }

  #[test]
  fn decoy_round_trips_spec_fields_and_all_entries() {
    let doc = "apiVersion: v1
kind: Config
preferences: {colors: true}
current-context: k3s-local
contexts:
- name: k3s-local
  context: {cluster: k3s, user: admin, namespace: platform}
- name: staging
  context: {cluster: stg, user: stg-user, namespace: stg-ns}
clusters:
- name: k3s
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=, tls-server-name: api.internal, insecure-skip-tls-verify: false}
- name: stg
  cluster: {server: https://10.1.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: admin
  user: {token: k3s-admin-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ, username: ivan, as: platform-sa}
- name: stg-user
  user: {token: stg-real-token}
";
    let adapted = adapt_doc(doc);
    let decoy = &adapted.decoy;
    assert!(decoy.contains("namespace: platform"), "{decoy}");
    assert!(decoy.contains("namespace: stg-ns"), "{decoy}");
    assert!(decoy.contains("tls-server-name: api.internal"), "{decoy}");
    assert!(decoy.contains("insecure-skip-tls-verify: false"), "{decoy}");
    assert!(decoy.contains("preferences"), "{decoy}");
    assert!(decoy.contains("server: https://10.1.0.1:6443"), "{decoy}");
    assert!(decoy.contains("username: ivan"), "{decoy}");
    assert!(decoy.contains("as: platform-sa"), "{decoy}");
    assert!(!decoy.contains("k3s-admin-token"), "no real token survives: {decoy}");
    assert!(!decoy.contains("stg-real-token"), "no real token survives in any user: {decoy}");
    assert!(
      !decoy.contains("Q0E=") && !decoy.contains("Q1RFU1Q="),
      "no real CA survives in any cluster: {decoy}"
    );
    assert!(!decoy.contains("Q0VSVA=="), "no real pair survives: {decoy}");
    assert_eq!(decoy.matches("token: ").count(), 2, "each user keeps a decoy token: {decoy}");
  }

  #[test]
  fn token_only_user_takes_plain_tls_while_pair_users_take_mtls() {
    // Only unmasked fixture text is touched here, so the bearer value never
    // appears in this test.
    let token_doc = BEARER_DOC.replace(", client-certificate-data: Q0VSVA==, client-key-data: S0VZ", "");
    let token_rules = rules_from(&adapt_doc(&token_doc).fragment);
    let token_user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let token_rule = token_rules.get(&token_user.label).expect("rule present");
    let token_tls = token_rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert_eq!(
      token_tls.guest_tls_mode,
      GuestTlsMode::Tls,
      "no client pair, so the proxy must not ask the guest for a client certificate"
    );
    let marker = "user: {";
    let fields_at = BEARER_DOC.find(marker).expect("user line") + marker.len();
    let pair_at = BEARER_DOC[fields_at..].find(", client-certificate-data").expect("pair fields") + fields_at + 2;
    let mut pair_doc = BEARER_DOC.to_string();
    pair_doc.replace_range(fields_at..pair_at, "");
    let pair_rules = rules_from(&adapt_doc(&pair_doc).fragment);
    let pair_user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let pair_rule = pair_rules.get(&pair_user.label).expect("rule present");
    let pair_tls = pair_rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert_eq!(
      pair_tls.guest_tls_mode,
      GuestTlsMode::Mtls,
      "pair users still swap the client certificate"
    );
  }

  #[test]
  fn cert_only_user_maps_to_an_identity_grant() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
    );
    let adapted = adapt_doc(&doc);
    let rules = rules_from(&adapted.fragment);
    let user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let decoy = rule_decoy(&rules[&user.label]);
    assert!(
      adapted.decoy.contains(&decoy),
      "a cert-only user still gets its grant decoy as a token: {}",
      adapted.decoy
    );
    assert!(rules[&user.label].value.is_some(), "identity grant still resolves");
  }

  #[test]
  fn cert_only_grant_value_is_a_single_header_line() {
    let pem = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n";
    let encoded = STANDARD.encode(pem);
    let doc = format!(
      "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {{cluster: prod, user: admin}}
clusters:
- name: prod
  cluster: {{server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}}
users:
- name: admin
  user: {{client-certificate-data: {encoded}, client-key-data: S0VZ}}
"
    );
    let adapted = adapt_doc(&doc);
    let rules = rules_from(&adapted.fragment);
    let user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let value = rules[&user.label].value.as_ref().expect("grant value").expose_secret();
    assert!(!value.contains(['\n', '\r', '\0']), "grant value is one header line: {value:?}");
    assert!(value.contains("BEGIN CERTIFICATE") && value.contains("CERT"), "{value}");
  }

  #[test]
  fn file_refs_are_inlined_from_the_kubeconfig_directory() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(dir.path().join("ca.crt"), b"cluster-ca-bytes").unwrap();
    fs::write(nested.join("client.crt"), b"client-cert-bytes").unwrap();
    fs::write(nested.join("client.key"), b"client-key-bytes").unwrap();
    let source = nested.join("config");
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority: ../ca.crt}
users:
- name: alice
  user: {client-certificate: client.crt, client-key: client.key}
";
    let adapted = adapt(&source, doc.as_bytes(), &test_ca(), dir.path())
      .expect("file references adapt")
      .expect("kubeconfig");
    assert!(adapted.fragment.contains("https://10.0.0.1:6443"), "{}", adapted.fragment);
    assert!(adapted.decoy.contains("certificate-authority-data:"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("certificate-authority:"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("client-certificate-data:"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("client-key-data:"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("client-certificate:"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("client-key:"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("cluster-ca-bytes"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("client-cert-bytes"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("client-key-bytes"), "{}", adapted.decoy);
    let user = identities(&[ContextRef {
      source: source.as_path(),
      protocol: AmbientProtocol::KubernetesUser,
      name: "alice",
    }])
    .expect("identity")
    .into_iter()
    .next()
    .expect("one identity");
    let tls = rules_from(&adapted.fragment)[&user.label].tls.values().next().expect("tls").clone();
    assert_eq!(tls.guest_tls_mode, GuestTlsMode::Mtls);
  }

  #[test]
  fn inline_data_wins_over_a_file_reference() {
    let doc = BEARER_DOC
      .replace(
        "certificate-authority-data: Q0E=",
        "certificate-authority-data: Q0E=, certificate-authority: missing-ca.crt",
      )
      .replace(
        "client-certificate-data: Q0VSVA==, client-key-data: S0VZ",
        "client-certificate-data: Q0VSVA==, client-key-data: S0VZ, client-certificate: missing.crt, client-key: missing.key",
      );
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path())
      .expect("inline data adapts")
      .expect("kubeconfig");
    assert!(!adapted.decoy.contains("missing-ca.crt"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("missing.crt"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("missing.key"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("certificate-authority-data:"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("client-certificate-data:"), "{}", adapted.decoy);
  }

  #[test]
  fn missing_file_ref_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("config");
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority: missing-ca.crt}
users:
- name: alice
  user: {token: alice-token}
";
    let err = adapt(&source, doc.as_bytes(), &test_ca(), dir.path()).expect_err("a missing file fails closed");
    let text = err.to_string();
    assert!(text.contains("cannot read"), "{text}");
    assert!(text.contains("missing-ca.crt"), "{text}");
  }

  #[test]
  fn exec_plugins_are_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {exec: {command: aws-iam-authenticator}}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("exec fails closed");
    assert!(err.to_string().contains("exec credential plugins"), "{err}");
  }

  #[test]
  fn unknown_context_is_an_error() {
    let doc = BEARER_DOC.replace("current-context: k3s-local", "current-context: nope");
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("unknown context fails closed");
    assert!(err.to_string().contains("unknown context"), "{err}");
  }

  #[test]
  fn half_pair_is_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("half pair fails closed");
    assert!(err.to_string().contains("half of the client pair"), "{err}");
  }

  #[test]
  fn plain_http_server_is_an_error() {
    let doc = BEARER_DOC.replace("https://10.0.0.1:6443", "http://10.0.0.1:8080");
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("plain HTTP fails closed");
    assert!(err.to_string().contains("plain HTTP"), "{err}");
  }

  fn rule_decoy(rule: &RuleCfg) -> String {
    let value = rule.value.as_ref().expect("grant value").expose_secret();
    let scopes: Vec<EndpointScope> = rule.allow.iter().map(|entry| entry.parse().expect("allow entry")).collect();
    decoy_for_rule(&rule.env, None, &scopes, value.len()).0
  }

  #[test]
  fn two_contexts_on_different_servers_grant_each_user() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
- name: staging
  context: {cluster: staging, user: bob}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: alice
  user: {token: alice-token}
- name: bob
  user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 2, "one grant per user: {}", adapted.fragment);
    let mut modes = Vec::new();
    let mut decoys = Vec::new();
    for rule in rules.values() {
      let tls = rule.tls.values().next().expect("tls entry");
      modes.push(tls.guest_tls_mode);
      decoys.push(rule_decoy(rule));
    }
    assert!(modes.contains(&GuestTlsMode::Tls), "bearer user stays plain TLS: {modes:?}");
    assert!(modes.contains(&GuestTlsMode::Mtls), "client pair stays mutual TLS: {modes:?}");
    let allows: Vec<&str> = rules.values().flat_map(|rule| rule.allow.iter().map(String::as_str)).collect();
    assert!(allows.contains(&"https://10.0.0.1:6443"), "{allows:?}");
    assert!(allows.contains(&"https://10.2.0.1:6443"), "{allows:?}");
    assert_ne!(decoys[0], decoys[1], "each user has its own decoy");
    let token_decoy = rules
      .values()
      .find(|rule| rule.tls.values().any(|tls| tls.guest_tls_mode == GuestTlsMode::Tls))
      .map(rule_decoy)
      .expect("bearer grant");
    assert!(
      adapted.decoy.contains(&token_decoy),
      "guest file carries the bearer decoy: {}",
      adapted.decoy
    );
    let cert_decoy = rules
      .values()
      .find(|rule| rule.tls.values().any(|tls| tls.guest_tls_mode == GuestTlsMode::Mtls))
      .map(rule_decoy)
      .expect("cert grant");
    assert!(
      adapted.decoy.contains(&cert_decoy),
      "guest file carries the cert user's decoy token: {}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: prod"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("alice-token"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("Q0VSVA=="), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("Q0E=") && !adapted.decoy.contains("Q1RFU1Q="),
      "{}",
      adapted.decoy
    );
  }

  #[test]
  fn two_token_users_on_one_server_each_get_a_grant() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: shared, user: alice}
- name: staging
  context: {cluster: shared, user: bob}
clusters:
- name: shared
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: alice
  user: {token: alice-token}
- name: bob
  user: {token: bob-token}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 2, "token users on one server are two grants: {}", adapted.fragment);
    let decoys: Vec<String> = rules.values().map(rule_decoy).collect();
    assert_ne!(decoys[0], decoys[1]);
    assert!(decoys.iter().all(|decoy| adapted.decoy.contains(decoy)), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("alice-token") && !adapted.decoy.contains("bob-token"),
      "{}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
  }

  #[test]
  fn token_user_beside_a_client_cert_on_one_server_is_granted() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: shared, user: alice}
- name: staging
  context: {cluster: shared, user: bob}
clusters:
- name: shared
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: alice
  user: {token: alice-token}
- name: bob
  user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(
      rules.len(),
      2,
      "a token user beside one client certificate is two grants: {}",
      adapted.fragment
    );
    let decoys: Vec<String> = rules.values().map(rule_decoy).collect();
    assert_ne!(decoys[0], decoys[1]);
    assert!(
      decoys.iter().all(|decoy| adapted.decoy.contains(decoy)),
      "the cert user token is its grant decoy too: {}",
      adapted.decoy
    );
    assert!(
      !adapted.decoy.contains("alice-token") && !adapted.decoy.contains("Q0VSVA=="),
      "{}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
  }

  #[test]
  fn merged_files_keep_the_defining_path_on_the_identity() {
    let first = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: alice
  user: {token: alice-token}
";
    let second = "apiVersion: v1
kind: Config
current-context: staging
contexts:
- name: prod
  context: {cluster: evil, user: mallory}
- name: staging
  context: {cluster: staging, user: bob}
clusters:
- name: evil
  cluster: {server: https://10.9.0.9:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: mallory
  user: {token: mallory-token}
- name: bob
  user: {token: bob-token}
";
    let first_path = Path::new("/home/ivan/.kube/first.yaml");
    let second_path = Path::new("/home/ivan/.kube/second.yaml");
    let dir = tempfile::tempdir().unwrap();
    let adapted = adapt_sources(
      &[(first_path, first.as_bytes()), (second_path, second.as_bytes())],
      &test_ca(),
      dir.path(),
    )
    .expect("adapt parses")
    .expect("merged kubeconfig");
    let rules = rules_from(&adapted.fragment);
    let alice = identities(&[ContextRef {
      source: first_path,
      protocol: AmbientProtocol::KubernetesUser,
      name: "alice",
    }])
    .expect("alice identity")
    .into_iter()
    .next()
    .expect("alice");
    let bob = identities(&[ContextRef {
      source: second_path,
      protocol: AmbientProtocol::KubernetesUser,
      name: "bob",
    }])
    .expect("bob identity")
    .into_iter()
    .next()
    .expect("bob");
    assert!(rules.contains_key(&alice.label), "{}", adapted.fragment);
    assert!(rules.contains_key(&bob.label), "{}", adapted.fragment);
    assert_ne!(alice.label, bob.label);
    assert!(!adapted.fragment.contains("https://10.9.0.9:6443"), "{}", adapted.fragment);
    assert!(adapted.decoy.contains("name: evil"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("mallory-token"), "{}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("user: mallory"),
      "the first prod user stays alice: {}",
      adapted.decoy
    );
  }

  #[test]
  fn one_user_on_two_servers_is_one_grant() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: a, user: alice}
- name: staging
  context: {cluster: b, user: alice}
clusters:
- name: a
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: b
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: alice
  user: {token: alice-token}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1, "a shared user is one grant: {}", adapted.fragment);
    let user = kube_identity(AmbientProtocol::KubernetesUser, "alice");
    let rule = rules.get(&user.label).expect("grant labeled by the user identity");
    assert!(rule.allow.iter().any(|entry| entry == "https://10.0.0.1:6443"), "{:?}", rule.allow);
    assert!(rule.allow.iter().any(|entry| entry == "https://10.2.0.1:6443"), "{:?}", rule.allow);
    let cluster_a = kube_identity(AmbientProtocol::KubernetesCluster, "a");
    let cluster_b = kube_identity(AmbientProtocol::KubernetesCluster, "b");
    let ca_name = |rule: &RuleCfg, server: &str, label: &str| {
      rule
        .tls
        .get(server)
        .and_then(|tls| tls.root_cert.as_ref())
        .is_some_and(|path| path.ends_with(format!("{label}.ca.crt")))
    };
    assert!(ca_name(rule, "https://10.0.0.1:6443", &cluster_a.label), "{:?}", rule.tls);
    assert!(ca_name(rule, "https://10.2.0.1:6443", &cluster_b.label), "{:?}", rule.tls);
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("alice-token"), "{}", adapted.decoy);
  }

  #[test]
  fn two_client_cert_users_on_one_server_each_get_a_grant() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: shared, user: alice}
- name: staging
  context: {cluster: shared, user: bob}
clusters:
- name: shared
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: alice
  user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
- name: bob
  user: {client-certificate-data: Qk9C, client-key-data: S0VZ}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(
      rules.len(),
      2,
      "client-certificate users on one server are two grants: {}",
      adapted.fragment
    );
    assert!(
      rules
        .values()
        .all(|rule| rule.allow.iter().any(|entry| entry == "https://10.0.0.1:6443")),
      "{}",
      adapted.fragment
    );
    assert!(
      rules
        .values()
        .all(|rule| rule.tls.values().all(|tls| tls.guest_tls_mode == GuestTlsMode::Mtls)),
      "{rules:?}"
    );
    let decoys: Vec<String> = rules.values().map(rule_decoy).collect();
    assert_ne!(decoys[0], decoys[1]);
    assert!(
      decoys.iter().all(|decoy| adapted.decoy.contains(decoy)),
      "each cert user token is its grant decoy: {}",
      adapted.decoy
    );
    assert!(
      !adapted.decoy.contains("Q0VSVA==") && !adapted.decoy.contains("Qk9C"),
      "{}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
  }

  #[test]
  fn cert_users_beside_the_current_context_are_granted() {
    let doc = "apiVersion: v1
kind: Config
current-context: dev
contexts:
- name: dev
  context: {cluster: dev, user: carol}
- name: prod
  context: {cluster: shared, user: alice}
- name: staging
  context: {cluster: shared, user: bob}
clusters:
- name: dev
  cluster: {server: https://10.9.0.1:6443, certificate-authority-data: Q0E=}
- name: shared
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: carol
  user: {token: carol-token}
- name: alice
  user: {client-certificate-data: Q0VSVA==, client-key-data: S0VZ}
- name: bob
  user: {client-certificate-data: Qk9C, client-key-data: S0VZ}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 3, "every derivable user is a grant: {}", adapted.fragment);
    let decoys: Vec<String> = rules.values().map(rule_decoy).collect();
    assert!(
      decoys.iter().all(|decoy| adapted.decoy.contains(decoy)),
      "every granted user token is its grant decoy: {}",
      adapted.decoy
    );
    assert!(adapted.fragment.contains("https://10.0.0.1:6443"), "{}", adapted.fragment);
    assert!(adapted.fragment.contains("https://10.9.0.1:6443"), "{}", adapted.fragment);
    assert!(
      adapted.decoy.contains("name: prod") && adapted.decoy.contains("name: staging"),
      "{}",
      adapted.decoy
    );
    assert!(
      !adapted.decoy.contains("Q0VSVA==") && !adapted.decoy.contains("Qk9C"),
      "{}",
      adapted.decoy
    );
    assert!(!adapted.decoy.contains("carol-token"), "{}", adapted.decoy);
  }

  #[test]
  fn distinct_user_spellings_do_not_share_a_label() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod.eu
contexts:
- name: prod.eu
  context: {cluster: a, user: prod.eu}
- name: prod-eu
  context: {cluster: b, user: prod-eu}
clusters:
- name: a
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: b
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: prod.eu
  user: {token: left-token}
- name: prod-eu
  user: {token: right-token}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    let left = kube_identity(AmbientProtocol::KubernetesUser, "prod.eu");
    let right = kube_identity(AmbientProtocol::KubernetesUser, "prod-eu");
    assert_ne!(left.label, right.label);
    assert!(rules.contains_key(&left.label), "{}", adapted.fragment);
    assert!(rules.contains_key(&right.label), "{}", adapted.fragment);
    assert_ne!(rule_decoy(&rules[&left.label]), rule_decoy(&rules[&right.label]));
  }

  #[test]
  fn inactive_exec_context_is_skipped() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
- name: staging
  context: {cluster: staging, user: plugin}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://10.9.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: alice
  user: {token: alice-token}
- name: plugin
  user: {exec: {command: aws-iam-authenticator}}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1, "the exec context is not a grant: {}", adapted.fragment);
    assert!(!adapted.fragment.contains("https://10.9.0.1:6443"), "{}", adapted.fragment);
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("aws-iam-authenticator"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("alice-token"), "{}", adapted.decoy);
  }

  #[test]
  fn oidc_config_secrets_do_not_reach_the_guest() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
- name: staging
  context: {cluster: staging, user: oidc}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
- name: staging
  cluster: {server: https://10.2.0.1:6443, certificate-authority-data: Q1RFU1Q=}
users:
- name: alice
  user: {token: alice-token}
- name: oidc
  user: {auth-provider: {name: oidc, config: {access-token: oidc-access-token, id-token: oidc-id-token, refresh-token: oidc-refresh-token, client-secret: oidc-client-secret}}}
";
    let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let adapted = tracing::subscriber::with_default(WarnCapture(std::sync::Arc::clone(&lines)), || adapt_doc(doc));
    for secret in [
      "alice-token",
      "oidc-access-token",
      "oidc-id-token",
      "oidc-refresh-token",
      "oidc-client-secret",
    ] {
      assert!(!adapted.decoy.contains(secret), "{secret} survives: {}", adapted.decoy);
    }
    for secret in ["oidc-access-token", "oidc-id-token", "oidc-refresh-token", "oidc-client-secret"] {
      assert!(
        !adapted.fragment.contains(secret),
        "{secret} is a grant value: {}",
        adapted.fragment
      );
    }
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1, "an auth-provider-only user is not a grant: {}", adapted.fragment);
    assert!(!adapted.fragment.contains("https://10.2.0.1:6443"), "{}", adapted.fragment);
    let oidc = kube_identity(AmbientProtocol::KubernetesUser, "oidc");
    assert!(
      !adapted.decoy.contains(&oidc.secret()),
      "auth-provider config does not carry the grant decoy: {}",
      adapted.decoy
    );
    assert!(adapted.decoy.contains("name: staging"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("name: oidc"), "{}", adapted.decoy);
    let logged = lines.lock().unwrap().join("\n");
    assert!(logged.contains("staging"), "{logged}");
    assert!(logged.contains("auth-provider"), "{logged}");
  }

  #[test]
  fn current_auth_provider_fails_the_file() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {auth-provider: {name: oidc, config: {access-token: oidc-access-token}}}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("current auth-provider fails the file");
    let text = err.to_string();
    assert!(text.contains("uses an auth-provider"), "{text}");
    assert!(!text.contains("oidc-access-token"), "{text}");
  }

  #[test]
  fn token_beside_auth_provider_keeps_the_token_grant() {
    let doc = "apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: prod
  context: {cluster: prod, user: alice}
clusters:
- name: prod
  cluster: {server: https://10.0.0.1:6443, certificate-authority-data: Q0E=}
users:
- name: alice
  user: {token: alice-token, auth-provider: {name: oidc, config: {access-token: oidc-access-token, client-secret: oidc-client-secret}}}
";
    let adapted = adapt_doc(doc);
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1, "{}", adapted.fragment);
    assert!(adapted.fragment.contains("https://10.0.0.1:6443"), "{}", adapted.fragment);
    assert!(!adapted.fragment.contains("oidc-access-token"), "{}", adapted.fragment);
    assert!(!adapted.fragment.contains("oidc-client-secret"), "{}", adapted.fragment);
    assert!(!adapted.decoy.contains("alice-token"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("oidc-access-token"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("oidc-client-secret"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("token: "), "{}", adapted.decoy);
  }

  #[test]
  fn credentialless_user_is_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("nothing to swap fails closed");
    assert!(err.to_string().contains("nothing to substitute"), "{err}");
  }

  #[test]
  fn empty_token_does_not_read_the_access_token() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {token: \"\", auth-provider: {name: gcp, config: {access-token: gcp-token}}}",
    );
    let dir = tempfile::tempdir().unwrap();
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca(), dir.path()).expect_err("empty token is not a bearer");
    assert!(err.to_string().contains("nothing to substitute"), "{err}");
    assert!(!err.to_string().contains("gcp-token"), "{err}");
  }

  #[test]
  fn state_writes_and_stale_ones_prune() {
    let adapted = adapt_doc(BEARER_DOC);
    let dir = tempfile::tempdir().unwrap();
    let grants = dir.path().join("grants");
    write_state(&grants, &[adapted]).unwrap();
    let rules = grants.join("rules.d");
    let marker = fs::read_to_string(grants.join("arkham.toml")).unwrap();
    let user = kube_identity(AmbientProtocol::KubernetesUser, "admin");
    let cluster = kube_identity(AmbientProtocol::KubernetesCluster, "k3s");
    assert!(marker.contains(&format!("[rules.{}]", user.label)), "{marker}");
    assert!(rules.join(format!("{}.client.crt", user.label)).is_file());
    assert!(rules.join(format!("{}.ca.crt", cluster.label)).is_file());
    let stale = rules.join("kube-gone.crt");
    fs::write(&stale, "stale").unwrap();
    write_state(&grants, &[]).unwrap();
    assert!(!stale.exists(), "removed rewrites stop granting");
  }

  /// Kubeconfig sources adapt with no `envs`, stated or sniffed.
  #[test]
  fn kube_rewrites_adapt_stated_or_sniffed() {
    let dir = tempdir().unwrap();
    let home = tempdir().unwrap();
    let xdg = tempdir().unwrap();
    let _env = AmbientEnv::isolate(home.path(), xdg.path());
    let source = dir.path().join("k3s.yaml");
    fs::write(&source, KUBE_DOC).unwrap();
    let expander = build_expander(HashMap::new());
    let files = dir.path().join("files");
    let guests = dir.path().join("guests");
    for format in [None, Some(RewriteFormat::Kubeconfig)] {
      let outputs = write_rewrites(&RewriteInputs {
        files_dir: &files,
        root: dir.path(),
        rewrites: &[FileRewrite {
          source: source.clone(),
          dest: "{home}/.kube/config".to_string(),
          envs: Vec::new(),
          format,
        }],
        decoys: &[],
        env: &HashMap::new(),
        expander: &expander,
        home: "/home/eng",
        host_home: None,
        guests_dir: &guests,
      })
      .unwrap();
      assert_eq!(outputs.mounts.len(), 1);
      assert_eq!(outputs.grants.len(), 1);
      assert!(
        outputs.grants[0].fragment.contains("https://10.0.0.1:6443"),
        "{}",
        outputs.grants[0].fragment
      );
      let body = fs::read_to_string(&outputs.mounts[0].host).unwrap();
      assert!(body.contains("current-context: k3s-local"), "{body}");
      assert!(!body.contains("probe-token"), "no real credential survives: {body}");
      assert!(!outputs.mounts[0].ro, "a kubeconfig rewrite mounts writable");
    }
  }

  /// A stated kubeconfig format on a foreign file fails closed.
  #[test]
  fn stated_kubeconfig_on_plain_text_is_an_error() {
    let dir = tempdir().unwrap();
    let home = tempdir().unwrap();
    let xdg = tempdir().unwrap();
    let _env = AmbientEnv::isolate(home.path(), xdg.path());
    let source = dir.path().join("npmrc");
    fs::write(&source, "//registry.npmjs.org/:_authToken=real-secret-1\n").unwrap();
    let guests = dir.path().join("guests");
    let expander = build_expander(HashMap::new());
    let error = write_rewrites(&RewriteInputs {
      files_dir: &dir.path().join("files"),
      root: dir.path(),
      rewrites: &[FileRewrite {
        source,
        dest: "{home}/.npmrc".to_string(),
        envs: Vec::new(),
        format: Some(RewriteFormat::Kubeconfig),
      }],
      decoys: &[],
      env: &HashMap::new(),
      expander: &expander,
      home: "/home/eng",
      host_home: None,
      guests_dir: &guests,
    })
    .unwrap_err()
    .to_string();
    assert!(error.contains("does not parse as YAML"), "{error}");
  }
}
