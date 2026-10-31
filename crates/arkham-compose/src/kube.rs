//! Kubeconfig adapter for `file_rewrite`: a kubectl config file is a
//! differently structured form of the same information a rule holds, so the
//! adapter derives the grant from the file instead of asking the operator to
//! state it twice. Every derivable context maps. A non-current context that
//! cannot be derived is skipped. The file is the secret source, so a kube
//! entry stating `envs` is an error rather than a second source.
//!
//! Detection is structural: a YAML mapping with `kind: Config` and a
//! `clusters:` table takes the adapter path, everything else keeps the raw
//! byte-swap. The decoy twin keeps the server (transparent capture makes the
//! destination the identity) and swaps the trust and identity: arkham's CA
//! and a distinct decoy bearer per granted user. The guest presents no
//! client certificate.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use arkham_config::config::{RewriteFormat, fake_for};
use arkham_config::context::{AmbientProtocol, ContextIdentity, ContextRef, Presented, identities, require_distinct};
use arkham_config::grants::{EndpointScope, GuestTlsMode, HostPat, Scheme, decoy_for_rule};
use arkham_pki::ca::CertAuthority;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{Request, Uri};
use kube_client::client::ConfigExt;
use kube_client::config::{AuthInfo, Kubeconfig, KubeconfigError};
use secrecy::ExposeSecret;
use serde_yaml::{Mapping, Value, from_str};
use tower::{ServiceBuilder, ServiceExt};

use crate::adapt::{GrantFragment, RewriteAdapted, decode, materialize_client_tls, render_decoy, render_fragment};
use crate::error::Error;

/// Map a kubeconfig onto its grant fragment and decoy twin. Returns `None`
/// when the document is not a kubeconfig after all, leaving the caller on
/// the raw path.
///
/// # Errors
///
/// Returns an error when the document does not parse, names no usable
/// current context, states a non-HTTPS server, or carries no substitutable
/// credential.
pub(crate) async fn adapt(source: &Path, content: &[u8], ca: &CertAuthority) -> Result<Option<RewriteAdapted>, Error> {
  let text = String::from_utf8_lossy(content);
  let Some(config) = read_doc(source, &text)? else {
    return Ok(None);
  };
  let opened = open_all(&config, source).await?;
  let users = identities(&refs(
    source,
    AmbientProtocol::KubernetesUser,
    opened.iter().map(|item| item.user.as_str()),
  ))?;
  let clusters = identities(&refs(
    source,
    AmbientProtocol::KubernetesCluster,
    opened.iter().map(|item| item.cluster.as_str()),
  ))?;
  let decoys = decoys(&opened, &users);
  require_presented(source, &opened, &users, &decoys)?;
  let (fragment, materialized) = render(source, &opened, &users, &clusters)?;
  let decoy = decoy_doc(&text, source, ca, &decoys)?;
  Ok(Some(RewriteAdapted {
    fragment,
    decoy,
    materialized,
    decoy_files: Vec::new(),
  }))
}

type ClientPair = (Vec<u8>, Vec<u8>);
type Materialized = Vec<(String, Vec<u8>)>;

struct Opened {
  user: String,
  cluster: String,
  server: String,
  host: String,
  port: u16,
  scope: EndpointScope,
  token: Option<String>,
  pair: Option<ClientPair>,
  ca: Option<Vec<u8>>,
}

fn read_doc(file: &Path, text: &str) -> Result<Option<Kubeconfig>, Error> {
  let doc = match Kubeconfig::from_yaml(text) {
    Ok(doc) => doc,
    Err(KubeconfigError::Parse(source) | KubeconfigError::InvalidStructure(source)) => {
      return Err(Error::RewriteYaml {
        file: file.to_path_buf(),
        source,
      });
    }
    Err(source) => {
      return Err(Error::Kubeconfig {
        file: file.to_path_buf(),
        source: Box::new(source),
      });
    }
  };
  if doc.kind.as_deref() != Some("Config") {
    return Ok(None);
  }
  Ok(Some(doc))
}

async fn open_all(config: &Kubeconfig, file: &Path) -> Result<Vec<Opened>, Error> {
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
    match open_one(entry, config, file).await {
      Ok(item) => opened.push(item),
      Err(err) if entry.name == current => return Err(err),
      Err(err) => tracing::warn!(context = %entry.name, %err, "kube context skipped"),
    }
  }
  Ok(opened)
}

async fn open_one(entry: &kube_client::config::NamedContext, config: &Kubeconfig, file: &Path) -> Result<Opened, Error> {
  let Some(spec) = &entry.context else {
    return Err(invalid(file, format!("context `{}` names no `cluster` or no `user`", entry.name)));
  };
  let Some(user_name) = spec.user.as_deref().filter(|user| !user.is_empty()) else {
    return Err(invalid(file, format!("context `{}` names no `cluster` or no `user`", entry.name)));
  };
  if spec.cluster.is_empty() {
    return Err(invalid(file, format!("context `{}` names no `cluster` or no `user`", entry.name)));
  }
  let Some(cluster) = config.clusters.iter().find(|item| item.name == spec.cluster) else {
    return Err(invalid(file, format!("unknown cluster `{}`", spec.cluster)));
  };
  let Some(body) = &cluster.cluster else {
    return Err(invalid(file, format!("cluster `{}` states no `server`", cluster.name)));
  };
  let Some(server) = body.server.as_deref().filter(|server| !server.is_empty()) else {
    return Err(invalid(file, format!("cluster `{}` states no `server`", cluster.name)));
  };
  let scope = server_scope(file, server)?;
  let HostPat::Exact(host) = &scope.host else {
    return Err(invalid(file, format!("server `{server}` is not an exact host")));
  };
  let Some(named) = config.auth_infos.iter().find(|item| item.name == user_name) else {
    return Err(invalid(file, format!("unknown user `{user_name}`")));
  };
  let fallback = AuthInfo::default();
  let auth = named.auth_info.as_ref().unwrap_or(&fallback);
  if auth.client_certificate.is_some() || auth.client_key.is_some() || auth.token_file.is_some() || body.certificate_authority.is_some() {
    return Err(invalid(
      file,
      "uses file references; inline them first: `kubectl config view --flatten --minify`",
    ));
  }
  let (token, pair) = credential(auth, file, user_name).await?;
  let ca = decode(
    file,
    RewriteFormat::Kubeconfig,
    body.certificate_authority_data.as_deref(),
    "certificate-authority-data",
  )?;
  Ok(Opened {
    user: user_name.to_owned(),
    cluster: cluster.name.clone(),
    server: server.to_owned(),
    host: host.clone(),
    port: scope.port,
    scope,
    token,
    pair,
    ca,
  })
}

fn server_scope(file: &Path, server: &str) -> Result<EndpointScope, Error> {
  let scope: EndpointScope = server
    .parse()
    .map_err(|detail| invalid(file, format!("server `{server}` is not an allow entry: {detail}")))?;
  if scope.scheme != Scheme::Https {
    return Err(invalid(
      file,
      format!("server `{server}` is plain HTTP: the API server is TLS-only"),
    ));
  }
  Ok(scope)
}

async fn credential(auth: &AuthInfo, file: &Path, user: &str) -> Result<(Option<String>, Option<ClientPair>), Error> {
  let token = auth
    .token
    .as_ref()
    .map(ExposeSecret::expose_secret)
    .filter(|token| !token.is_empty())
    .map(str::to_owned);
  let cert = decode(
    file,
    RewriteFormat::Kubeconfig,
    auth.client_certificate_data.as_deref(),
    "client-certificate-data",
  )?;
  let key = decode(
    file,
    RewriteFormat::Kubeconfig,
    auth.client_key_data.as_ref().map(ExposeSecret::expose_secret),
    "client-key-data",
  )?;
  let pair = match (cert, key) {
    (None, None) => None,
    (Some(cert), Some(key)) => Some((cert, key)),
    _ => return Err(invalid(file, format!("user `{user}` carries half of the client pair"))),
  };
  if token.is_none() && pair.is_none() && (auth.exec.is_some() || auth.auth_provider.is_some()) {
    return Ok((Some(plugin_bearer(auth, file).await?), None));
  }
  if token.is_none() && pair.is_none() {
    return Err(invalid(
      file,
      format!("user `{user}` carries neither `token` nor a client pair: nothing to substitute"),
    ));
  }
  Ok((token, pair))
}

async fn plugin_bearer(auth: &AuthInfo, file: &Path) -> Result<String, Error> {
  let mut config = kube_client::Config::new(Uri::from_static("https://kubernetes.default.svc"));
  config.auth_info = auth.clone();
  let layer = ConfigExt::auth_layer(&config).map_err(|source| Error::KubeClient {
    file: file.to_path_buf(),
    source: Box::new(source),
  })?;
  let Some(layer) = layer else {
    let detail = if auth.exec.is_some() {
      "exec credential plugin returned a client certificate"
    } else {
      "auth-provider did not produce a bearer token"
    };
    return Err(invalid(file, detail));
  };
  let service = ServiceBuilder::new().layer(layer).service(tower::service_fn(echo_authorization));
  let header = match service.oneshot(Request::new(kube_client::client::Body::empty())).await {
    Ok(response) => response.into_body(),
    Err(err) => return Err(invalid(file, format!("credential plugin failed: {err}"))),
  };
  let Some(header) = header else {
    return Err(invalid(file, "credential plugin produced no Authorization header"));
  };
  let Some(token) = header.strip_prefix("Bearer ") else {
    return Err(invalid(file, "credential plugin produced no bearer token"));
  };
  if token.is_empty() {
    return Err(invalid(file, "credential plugin produced no bearer token"));
  }
  Ok(token.to_owned())
}

async fn echo_authorization(request: Request<kube_client::client::Body>) -> Result<http::Response<Option<String>>, tower::BoxError> {
  let header = request
    .headers()
    .get(http::header::AUTHORIZATION)
    .and_then(|value| value.to_str().ok())
    .map(str::to_owned);
  Ok(http::Response::new(header))
}

fn refs<'a>(file: &'a Path, protocol: AmbientProtocol, names: impl Iterator<Item = &'a str>) -> Vec<ContextRef<'a>> {
  let mut seen = BTreeSet::new();
  names
    .filter(|name| seen.insert(*name))
    .map(|name| ContextRef {
      source: file,
      protocol,
      name,
    })
    .collect()
}

fn decoys(opened: &[Opened], users: &[ContextIdentity]) -> BTreeMap<String, String> {
  let mut decoys = BTreeMap::new();
  for id in users {
    let Some(first) = opened.iter().find(|item| item.user == id.name) else {
      continue;
    };
    let mut allow = Vec::new();
    for item in opened.iter().filter(|item| item.user == id.name) {
      if allow.iter().any(|scope: &EndpointScope| scope == &item.scope) {
        continue;
      }
      allow.push(item.scope.clone());
    }
    let (token, _) = decoy_for_rule(&id.env(), None, &allow, grant_value(first).len());
    decoys.insert(id.name.clone(), token);
  }
  decoys
}

fn require_presented(file: &Path, opened: &[Opened], users: &[ContextIdentity], decoys: &BTreeMap<String, String>) -> Result<(), Error> {
  let mut presented = Vec::new();
  for item in opened {
    let Some(token) = decoys.get(&item.user) else {
      return Err(invalid(file, format!("user `{}` has no decoy", item.user)));
    };
    let Some(identity) = users.iter().find(|id| id.name == item.user) else {
      return Err(invalid(file, format!("user `{}` has no identity", item.user)));
    };
    presented.push(Presented {
      identity,
      host: item.host.as_str(),
      port: item.port,
      decoy: token.as_bytes(),
    });
  }
  require_distinct(&presented)?;
  Ok(())
}

fn grant_value(item: &Opened) -> String {
  if let Some(token) = &item.token {
    return token.clone();
  }
  let pem = item.pair.as_ref().map(|(cert, _)| cert.as_slice()).unwrap_or_default();
  single_line(&String::from_utf8_lossy(pem))
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

fn render(
  file: &Path,
  opened: &[Opened],
  users: &[ContextIdentity],
  clusters: &[ContextIdentity],
) -> Result<(String, Materialized), Error> {
  let mut fragment = String::new();
  let mut materialized = Vec::new();
  for id in users {
    let peers: Vec<&Opened> = opened.iter().filter(|item| item.user == id.name).collect();
    let Some(first) = peers.first() else {
      continue;
    };
    let (mut base, pair_files) = materialize_client_tls(&id.label, first.pair.clone(), None);
    base.guest_tls_mode = GuestTlsMode::Tls;
    materialized.extend(pair_files);
    let mut allow = Vec::new();
    let mut tls = BTreeMap::new();
    for peer in &peers {
      if allow.iter().any(|url| url == &peer.server) {
        continue;
      }
      let Some(cluster_id) = clusters.iter().find(|cluster| cluster.name == peer.cluster) else {
        return Err(invalid(file, format!("cluster `{}` has no identity", peer.cluster)));
      };
      let (ca_tls, ca_files) = materialize_client_tls(&cluster_id.label, None, peer.ca.clone());
      let mut entry = base.clone();
      entry.root_cert = ca_tls.root_cert;
      allow.push(peer.server.clone());
      tls.insert(peer.server.clone(), entry);
      materialized.extend(ca_files);
    }
    fragment.push_str(&render_fragment(
      file,
      &id.label,
      &GrantFragment {
        env: id.env(),
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
  }
  Ok((fragment, materialized))
}

/// Edits the source YAML in place so unmodeled fields round-trip. An existing
/// `certificate-authority-data` becomes arkham's CA. A granted user gets a decoy bearer.
fn decoy_doc(text: &str, source: &Path, ca: &CertAuthority, decoys: &BTreeMap<String, String>) -> Result<String, Error> {
  let mut root: Value = from_str(text).map_err(|err| Error::RewriteYaml {
    file: source.to_path_buf(),
    source: err,
  })?;
  let guest_ca = Value::String(STANDARD.encode(ca.cert_pem()));
  for cluster in entries_mut(&mut root, "clusters") {
    let Some(inner) = cluster
      .get_mut(Value::String("cluster".to_string()))
      .and_then(Value::as_mapping_mut)
    else {
      continue;
    };
    let ca_data = Value::String("certificate-authority-data".to_string());
    if inner.contains_key(&ca_data) {
      inner.insert(ca_data, guest_ca.clone());
    }
    inner.remove(Value::String("certificate-authority".to_string()));
  }
  for user in entries_mut(&mut root, "users") {
    let name = user
      .get(Value::String("name".to_string()))
      .and_then(Value::as_str)
      .unwrap_or_default()
      .to_string();
    let Some(inner) = user.get_mut(Value::String("user".to_string())).and_then(Value::as_mapping_mut) else {
      continue;
    };
    let placeholder = || fake_for(&format!("KUBE_{}", name.to_uppercase().replace(['-', '.'], "_")), None);
    if let Some(decoy) = decoys.get(&name) {
      inner.insert(Value::String("token".to_string()), Value::String(decoy.clone()));
    } else if inner.contains_key(Value::String("token".to_string())) {
      inner.insert(Value::String("token".to_string()), Value::String(placeholder()));
    }
    inner.remove(Value::String("client-certificate-data".to_string()));
    inner.remove(Value::String("client-key-data".to_string()));
    inner.remove(Value::String("client-certificate".to_string()));
    inner.remove(Value::String("client-key".to_string()));
    inner.remove(Value::String("tokenFile".to_string()));
    inner.remove(Value::String("auth-provider".to_string()));
    if inner.contains_key(Value::String("password".to_string())) {
      inner.insert(Value::String("password".to_string()), Value::String(placeholder()));
    }
    inner.remove(Value::String("exec".to_string()));
  }
  render_decoy(&root)
}

/// The `key` list of `root` as mutable mappings; entries that are not
/// mappings contribute nothing.
fn entries_mut<'a>(root: &'a mut Value, key: &str) -> Vec<&'a mut Mapping> {
  root
    .as_mapping_mut()
    .and_then(|map| map.get_mut(Value::String(key.to_string())))
    .and_then(Value::as_sequence_mut)
    .map_or_else(Vec::new, |seq| seq.iter_mut().filter_map(Value::as_mapping_mut).collect())
}

fn invalid(file: &Path, detail: impl Into<String>) -> Error {
  Error::RewriteInvalid {
    file: file.to_path_buf(),
    format: RewriteFormat::Kubeconfig,
    detail: detail.into(),
  }
}

#[cfg(test)]
mod tests {
  use std::fmt::Write as _;
  use std::fs;
  use std::os::unix::fs::PermissionsExt;
  use std::sync::{Arc, Mutex};

  use super::*;
  use crate::adapt::write_state;
  use crate::expand::*;
  use crate::rewrites::*;
  use crate::test_support::*;
  use arkham_config::config::FileRewrite;
  use arkham_config::config::RuleCfg;
  use serde::Deserialize;
  use std::collections::HashMap;
  use tempfile::tempdir;

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

  async fn adapt_doc(doc: &str) -> RewriteAdapted {
    adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca())
      .await
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

  fn user_id(name: &str) -> ContextIdentity {
    identities(&[ContextRef {
      source: Path::new(SOURCE),
      protocol: AmbientProtocol::KubernetesUser,
      name,
    }])
    .unwrap()
    .into_iter()
    .next()
    .unwrap()
  }

  #[tokio::test]
  async fn foreign_content_is_not_a_kubeconfig() {
    let npmrc = "//registry.npmjs.org/:_authToken=secret";
    let err = adapt(Path::new(SOURCE), npmrc.as_bytes(), &test_ca())
      .await
      .expect_err("plain text fails closed");
    assert!(err.to_string().contains("does not parse as YAML"), "{err}");
  }

  #[tokio::test]
  async fn label_comes_from_the_user_identity() {
    let label = user_id("admin").label;
    let adapted = adapt_doc(BEARER_DOC).await;
    assert!(adapted.fragment.contains(&format!("[rules.{label}]")), "{}", adapted.fragment);
  }

  #[tokio::test]
  async fn fragment_holds_the_grant_and_parses_as_a_rule() {
    let adapted = adapt_doc(BEARER_DOC).await;
    let rules = rules_from(&adapted.fragment);
    let rule = rules.get(&user_id("admin").label).expect("rule present");
    assert_eq!(rule.env, user_id("admin").env());
    assert_eq!(rule.allow, vec!["https://10.0.0.1:6443".to_string()]);
    assert_eq!(rule.registry, Some(false));
    assert!(rule.value.is_some(), "bearer token is the inline real value");
    let tls = rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert!(
      tls
        .client_cert
        .as_ref()
        .is_some_and(|path| path.to_string_lossy().ends_with(".client.crt"))
    );
    assert!(
      tls
        .root_cert
        .as_ref()
        .is_some_and(|path| path.to_string_lossy().ends_with(".ca.crt"))
    );
    assert_eq!(tls.guest_tls_mode, GuestTlsMode::Tls);
    assert!(tls.guest_cert.is_none(), "the guest presents no client certificate");
    assert_eq!(adapted.materialized.len(), 3, "pair plus CA materialize beside the fragment");
  }

  #[tokio::test]
  async fn decoy_keeps_the_server_and_swaps_trust_identity_and_token() {
    let adapted = adapt_doc(BEARER_DOC).await;
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
      !adapted.decoy.contains("client-certificate-data:"),
      "guest carries no client certificate: {}",
      adapted.decoy
    );
    assert!(!adapted.decoy.contains("exec:"), "guest carries no exec plugin: {}", adapted.decoy);
    assert!(
      !adapted.decoy.contains("auth-provider:"),
      "guest carries no auth-provider: {}",
      adapted.decoy
    );
  }

  #[tokio::test]
  async fn decoy_round_trips_spec_fields_and_all_entries() {
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
    let adapted = adapt_doc(doc).await;
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
    assert!(
      !decoy.contains("client-certificate-data:"),
      "guest carries no client certificate: {decoy}"
    );
    assert!(!decoy.contains("exec:"), "{decoy}");
    assert!(!decoy.contains("auth-provider:"), "{decoy}");
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 2, "each granted user is its own rule");
    for rule in rules.values() {
      for tls in rule.tls.values() {
        assert_eq!(tls.guest_tls_mode, GuestTlsMode::Tls);
        assert!(tls.guest_cert.is_none());
      }
    }
    let parsed: Value = from_str(decoy).unwrap();
    let tokens: Vec<&str> = parsed["users"]
      .as_sequence()
      .unwrap()
      .iter()
      .map(|user| user["user"]["token"].as_str().unwrap())
      .collect();
    assert_eq!(tokens.len(), 2);
    assert_ne!(tokens[0], tokens[1], "granted users do not share a decoy bearer");
  }

  #[tokio::test]
  async fn token_and_pair_users_both_take_plain_tls() {
    // Only unmasked fixture text is touched here, so the bearer value never
    // appears in this test.
    let token_doc = BEARER_DOC.replace(", client-certificate-data: Q0VSVA==, client-key-data: S0VZ", "");
    let token_rules = rules_from(&adapt_doc(&token_doc).await.fragment);
    let token_rule = token_rules.get(&user_id("admin").label).expect("rule present");
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
    let pair_rules = rules_from(&adapt_doc(&pair_doc).await.fragment);
    let pair_rule = pair_rules.get(&user_id("admin").label).expect("rule present");
    let pair_tls = pair_rule.tls.get("https://10.0.0.1:6443").expect("tls keyed by the allow entry");
    assert_eq!(
      pair_tls.guest_tls_mode,
      GuestTlsMode::Tls,
      "pair users present a decoy bearer, not a client certificate"
    );
    assert!(pair_tls.client_cert.is_some(), "the host grant keeps the client certificate");
    assert!(pair_tls.guest_cert.is_none());
  }

  #[tokio::test]
  async fn cert_only_user_maps_to_an_identity_grant() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {client-certificate-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUIKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=, client-key-data: S0VZ}",
    );
    let adapted = adapt_doc(&doc).await;
    assert!(
      adapted.decoy.contains("token: "),
      "cert users still get a decoy bearer: {}",
      adapted.decoy
    );
    assert!(!adapted.decoy.contains("client-certificate-data:"), "{}", adapted.decoy);
    let rules = rules_from(&adapted.fragment);
    let value = rules[&user_id("admin").label]
      .value
      .as_ref()
      .expect("identity grant still resolves");
    let text = value.expose_secret();
    assert!(!text.contains('\n') && !text.contains('\r'), "{text}");
    assert!(text.contains("BEGIN CERTIFICATE"), "{text}");
  }

  #[tokio::test]
  async fn file_refs_are_an_error() {
    let doc = BEARER_DOC.replace("certificate-authority-data: Q0E=", "certificate-authority: ca.crt");
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca())
      .await
      .expect_err("file refs fail closed");
    assert!(err.to_string().contains("inline them first"), "{err}");
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn exec_plugin_token_lands_in_the_host_grant() {
    let dir = tempfile::tempdir().unwrap();
    let plugin = dir.path().join("exec-plugin");
    fs::write(
      &plugin,
      "#!/bin/sh\nprintf '%s\\n' '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"plugin-token\"}}'\n",
    )
    .unwrap();
    fs::set_permissions(&plugin, fs::Permissions::from_mode(0o755)).unwrap();
    let doc = format!(
      "apiVersion: v1\nkind: Config\ncurrent-context: k3s-local\ncontexts:\n- name: k3s-local\n  context: {{cluster: k3s, user: admin}}\nclusters:\n- name: k3s\n  cluster: {{server: https://10.0.0.1:6443}}\nusers:\n- name: admin\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: {}\n      interactiveMode: Never\n",
      plugin.display(),
    );
    let adapted = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca()).await.unwrap().unwrap();
    let rules = rules_from(&adapted.fragment);
    let value = rules[&user_id("admin").label].value.as_ref().unwrap();
    assert_eq!(value.expose_secret(), "plugin-token");
    assert!(!adapted.decoy.contains("plugin-token"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("token: "), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("exec:"), "{}", adapted.decoy);
    assert_eq!(
      rules[&user_id("admin").label].tls.values().next().unwrap().guest_tls_mode,
      GuestTlsMode::Tls
    );
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn exec_plugin_client_cert_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let plugin = dir.path().join("exec-plugin");
    fs::write(
      &plugin,
      "#!/bin/sh\nprintf '%s\\n' '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"clientCertificateData\":\"Y2VydA==\",\"clientKeyData\":\"a2V5\"}}'\n",
    )
    .unwrap();
    fs::set_permissions(&plugin, fs::Permissions::from_mode(0o755)).unwrap();
    let doc = format!(
      "apiVersion: v1\nkind: Config\ncurrent-context: k3s-local\ncontexts:\n- name: k3s-local\n  context: {{cluster: k3s, user: admin}}\nclusters:\n- name: k3s\n  cluster: {{server: https://10.0.0.1:6443}}\nusers:\n- name: admin\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: {}\n      interactiveMode: Never\n",
      plugin.display(),
    );
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca()).await.unwrap_err();
    assert!(err.to_string().contains("client certificate"), "{err}");
  }

  #[tokio::test(flavor = "current_thread")]
  async fn failed_exec_plugin_keeps_output_out_of_errors_and_logs() {
    const SECRET: &str = "arkham-fake-plugin-secret-9f3c";
    let dir = tempfile::tempdir().unwrap();
    let plugin = dir.path().join("exec-plugin-fail.sh");
    fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/exec-plugin-fail.sh"), &plugin).unwrap();
    fs::set_permissions(&plugin, fs::Permissions::from_mode(0o755)).unwrap();
    let command = plugin.display().to_string();
    let doc = format!(
      "apiVersion: v1\nkind: Config\ncurrent-context: current\ncontexts:\n- name: skipped\n  context: {{cluster: skipped, user: skipped-user}}\n- name: current\n  context: {{cluster: current, user: current-user}}\nclusters:\n- name: skipped\n  cluster: {{server: https://10.0.0.2:6443}}\n- name: current\n  cluster: {{server: https://10.0.0.1:6443}}\nusers:\n- name: skipped-user\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: \"{command}\"\n      interactiveMode: Never\n- name: current-user\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: \"{command}\"\n      interactiveMode: Never\n",
    );
    let lines = Arc::new(Mutex::new(Vec::new()));
    let _guard = tracing::subscriber::set_default(WarnCapture(Arc::clone(&lines)));
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca())
      .await
      .expect_err("failing exec plugin");
    drop(_guard);
    let logged = lines.lock().unwrap().join("\n");
    assert!(logged.contains("skipped"), "skipped context was not logged: {logged}");
    let display = err.to_string();
    let debug = format!("{err:?}");
    let mut leaks = Vec::new();
    if display.contains(SECRET) {
      leaks.push("display");
    }
    if debug.contains(SECRET) {
      leaks.push("debug");
    }
    if logged.contains(SECRET) {
      leaks.push("logs");
    }
    assert!(
      leaks.is_empty(),
      "secret leaked via {leaks:?}\ndisplay={display}\ndebug={debug}\nlogs={logged}"
    );
    assert!(display.contains("credential plugin failed"), "{display}");
    assert!(display.contains("exec"), "{display}");
    assert!(display.contains("exited 1"), "{display}");
  }

  #[tokio::test(flavor = "multi_thread")]
  async fn auth_provider_token_lands_in_the_host_grant() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {auth-provider: {name: oidc, config: {id-token: provider-token}}}",
    );
    let adapted = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca()).await.unwrap().unwrap();
    let rules = rules_from(&adapted.fragment);
    let value = rules[&user_id("admin").label].value.as_ref().unwrap();
    assert_eq!(value.expose_secret(), "provider-token");
    assert!(!adapted.decoy.contains("provider-token"), "{}", adapted.decoy);
    assert!(!adapted.decoy.contains("auth-provider:"), "{}", adapted.decoy);
    assert!(adapted.decoy.contains("token: "), "{}", adapted.decoy);
  }

  #[tokio::test]
  async fn unknown_context_is_an_error() {
    let doc = BEARER_DOC.replace("current-context: k3s-local", "current-context: nope");
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca())
      .await
      .expect_err("unknown context fails closed");
    assert!(err.to_string().contains("unknown context"), "{err}");
  }

  #[tokio::test]
  async fn half_pair_is_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==}",
    );
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca())
      .await
      .expect_err("half pair fails closed");
    assert!(err.to_string().contains("half of the client pair"), "{err}");
  }

  #[tokio::test]
  async fn plain_http_server_is_an_error() {
    let doc = BEARER_DOC.replace("https://10.0.0.1:6443", "http://10.0.0.1:8080");
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca())
      .await
      .expect_err("plain HTTP fails closed");
    assert!(err.to_string().contains("plain HTTP"), "{err}");
  }

  #[tokio::test]
  async fn credentialless_user_is_an_error() {
    let doc = BEARER_DOC.replace(
      "user: {token: k3s-token, client-certificate-data: Q0VSVA==, client-key-data: S0VZ}",
      "user: {}",
    );
    let err = adapt(Path::new(SOURCE), doc.as_bytes(), &test_ca())
      .await
      .expect_err("nothing to swap fails closed");
    assert!(err.to_string().contains("nothing to substitute"), "{err}");
  }

  #[tokio::test]
  async fn state_writes_and_stale_ones_prune() {
    let adapted = adapt_doc(BEARER_DOC).await;
    let dir = tempfile::tempdir().unwrap();
    let grants = dir.path().join("grants");
    write_state(&grants, &[adapted]).unwrap();
    let rules = grants.join("rules.d");
    let marker = fs::read_to_string(grants.join("arkham.toml")).unwrap();
    let label = user_id("admin").label;
    assert!(marker.contains(&format!("[rules.{label}]")), "{marker}");
    assert!(rules.join(format!("{label}.client.crt")).is_file());
    let stale = rules.join("kube-gone.crt");
    fs::write(&stale, "stale").unwrap();
    write_state(&grants, &[]).unwrap();
    assert!(!stale.exists(), "removed rewrites stop granting");
  }

  /// Kubeconfig sources adapt with no `envs`, stated or sniffed.
  #[tokio::test]
  async fn kube_rewrites_adapt_stated_or_sniffed() {
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
      .await
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
    }
  }

  /// A stated kubeconfig format on a foreign file fails closed.
  #[tokio::test]
  async fn stated_kubeconfig_on_plain_text_is_an_error() {
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
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("does not parse as YAML"), "{error}");
  }

  #[tokio::test]
  async fn one_user_two_contexts_is_one_grant() {
    let doc = "apiVersion: v1
kind: Config
current-context: a
contexts:
- name: a
  context: {cluster: a, user: admin}
- name: b
  context: {cluster: b, user: admin}
clusters:
- name: a
  cluster: {server: https://10.0.0.1:6443}
- name: b
  cluster: {server: https://10.1.0.1:6443}
users:
- name: admin
  user: {token: k3s-token}
";
    let rules = rules_from(&adapt_doc(doc).await.fragment);
    assert_eq!(rules.len(), 1);
    let mut allow = rules[&user_id("admin").label].allow.clone();
    allow.sort();
    assert_eq!(
      allow,
      vec!["https://10.0.0.1:6443".to_string(), "https://10.1.0.1:6443".to_string()]
    );
  }

  #[tokio::test]
  async fn inactive_context_failure_is_skipped() {
    let doc = BEARER_DOC.replace("clusters:", "- name: gone\n  context: {cluster: missing, user: ghost}\nclusters:");
    let adapted = adapt_doc(&doc).await;
    let rules = rules_from(&adapted.fragment);
    assert_eq!(rules.len(), 1);
    assert!(rules.contains_key(&user_id("admin").label));
  }

  struct WarnCapture(Arc<Mutex<Vec<String>>>);

  impl tracing::Subscriber for WarnCapture {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
      *metadata.level() <= tracing::Level::WARN
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
      tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
      let mut message = String::new();
      event.record(&mut WarnVisit(&mut message));
      self.0.lock().unwrap().push(message);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
  }

  struct WarnVisit<'a>(&'a mut String);

  impl tracing::field::Visit for WarnVisit<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
      let _ = write!(self.0, "{}={value:?};", field.name());
    }
  }
}
