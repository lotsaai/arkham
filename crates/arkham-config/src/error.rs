//! Crate error type: every fallible API returns `Result<T, Error>`.

use std::io::Error as IoError;
use std::path::PathBuf;

use crate::context::{AmbientProtocol, NameFault, PathFault};

use confique::Error as ConfiqueError;
use serde_json::Error as JsonError;
use toml::de::Error as TomlError;
use toml::ser::Error as TomlSerializeError;
use url::ParseError as UrlError;
use validator::ValidationErrors;

use crate::grants::{AmqpUriError, NatsUriError, Scheme};

/// Every way config loading, validation, and grant resolution can fail.
#[derive(Debug, thiserror::Error)]
pub enum Error {
  /// The working directory is unreadable.
  #[error(transparent)]
  CurrentDir(#[from] IoError),
  /// A config layer fails to load through confique.
  #[error(transparent)]
  LoadConfig(#[from] ConfiqueError),
  /// A file cannot be read.
  #[error("read {}: {source}", path.display())]
  ReadFile {
    /// File that could not be read.
    path: PathBuf,
    /// Underlying I/O failure.
    #[source]
    source: IoError,
  },
  /// A file does not parse as TOML.
  #[error("parse {}: {source}", path.display())]
  ParseFile {
    /// File that did not parse.
    path: PathBuf,
    /// Underlying parse failure.
    #[source]
    source: Box<TomlError>,
  },
  /// A rules file carries `rules` as something other than a table.
  #[error("{}: `rules` must be a table", path.display())]
  RulesNotTable {
    /// File carrying the bad `rules` value.
    path: PathBuf,
  },
  /// One rule entry does not deserialize.
  #[error("{}: rule `{label}`: {source}", path.display())]
  BadRule {
    /// File carrying the bad rule.
    path: PathBuf,
    /// Rule label.
    label: String,
    /// Underlying parse failure.
    #[source]
    source: Box<TomlError>,
  },
  /// Two rules share one env name.
  #[error("rules `{previous}` and `{label}` share env name `{env}`")]
  DuplicateEnv {
    /// First label claiming the name.
    previous: String,
    /// Second label claiming the name.
    label: String,
    /// Shared env name.
    env: String,
  },
  /// A rule fails the field checks on [`crate::RuleCfg`].
  #[error("rule `{label}`: {source}")]
  InvalidRule {
    /// Rule label.
    label: String,
    /// Field errors from the rule validator.
    #[source]
    source: ValidationErrors,
  },
  /// A rule states an empty inline value.
  #[error("rule `{label}`: `value` must not be empty")]
  EmptyValue {
    /// Rule label.
    label: String,
  },
  /// A connection-string rule states no fake `value` string; the connection
  /// string is the grant and one side cannot be missing.
  #[error("rule `{label}`: a connection-string rule states no `value` string")]
  ConnectionStringValueMissing {
    /// Rule label.
    label: String,
  },
  /// An `allow` entry does not parse as a URI grant.
  #[error("rule `{label}`: bad allow entry `{entry}`: {detail}")]
  BadAllow {
    /// Rule label.
    label: String,
    /// Offending entry.
    entry: String,
    /// Parse failure.
    detail: String,
  },
  /// Port 0 cannot be published.
  #[error("[workspace] ports: port 0 cannot be published")]
  PortZero,
  /// A capture listener port cannot be published.
  #[error("[workspace] port {port} is a capture listener port and cannot be published")]
  CapturePort {
    /// Offending port.
    port: u16,
  },
  /// A network name is blank or carries characters compose rejects.
  #[error("[workspace] networks `{name}` is not a plain network name ([A-Za-z0-9._-])")]
  NetworkInvalid {
    /// Offending name.
    name: String,
  },
  /// An extra host entry is not `host:ip` or `host=ip`.
  #[error("[workspace] extra_hosts `{entry}` must be `host:ip` or `host=ip`")]
  ExtraHostsInvalid {
    /// Offending entry.
    entry: String,
  },
  /// A host port is published twice across `ports` and `expose`.
  #[error("[workspace] host port {port} is published twice; give each expose mapping its own host port")]
  ExposeHostConflict {
    /// Offending host port.
    port: u16,
  },
  /// A connection-string rule states `allow` entries; the connection string
  /// is the grant.
  #[error("rule `{label}`: a connection-string rule states no allow entries; the connection string is the grant")]
  ConnectionStringAllow {
    /// Rule label.
    label: String,
  },
  /// A postgres connection string does not parse.
  #[error("rule `{label}`: {detail}")]
  PostgresScope {
    /// Rule label.
    label: String,
    /// Parse failure.
    detail: String,
  },
  /// A redis connection string does not parse.
  #[error("rule `{label}`: {detail}")]
  RedisScope {
    /// Rule label.
    label: String,
    /// Parse failure.
    detail: String,
  },
  /// An AMQP connection string does not parse.
  #[error("rule `{label}`: {source}")]
  AmqpScope {
    /// Rule label.
    label: String,
    /// Parse failure.
    #[source]
    source: AmqpUriError,
  },
  /// A connection-string rule names a scheme no vertical owns.
  #[error("rule `{label}`: scheme `{scheme:?}` owns no connection-string grant")]
  ConnectionStringScheme {
    /// Rule label.
    label: String,
    /// The scheme the rule's value stated.
    scheme: Scheme,
  },
  /// A `tls` entry names an env that is not the rule's own.
  #[error("rule `{label}`: tls config names `{key}` but the rule's env is `{env}`")]
  TlsEnvMismatch {
    /// Rule label.
    label: String,
    /// Offending key.
    key: String,
    /// Rule env name.
    env: String,
  },
  /// A postgres rule states its identity outside the libpq URL.
  #[error("rule `{label}`: postgres states the upstream identity in its libpq URL (`sslcert`/`sslkey`), never in the rule table")]
  PostgresIdentity {
    /// Rule label.
    label: String,
  },
  /// A `tls` entry carries only half of the client pair.
  #[error("rule `{label}`: entry `{entry}`: client_cert and client_key come together")]
  CertKeyPair {
    /// Rule label.
    label: String,
    /// Offending entry.
    entry: String,
  },
  /// A `tls` entry names an `allow` entry the rule does not grant.
  #[error("rule `{label}`: tls config names entry `{key}` the rule does not allow")]
  TlsUnknownEntry {
    /// Rule label.
    label: String,
    /// Offending key.
    key: String,
  },
  /// A plugin states no `allow` entries.
  #[error("plugin `{name}`: `allow` must not be empty")]
  PluginEmptyAllow {
    /// Plugin name.
    name: String,
  },
  /// A plugin `allow` entry does not parse as a URI grant.
  #[error("plugin `{name}`: invalid allow entry `{entry}`: {detail}")]
  PluginBadAllow {
    /// Plugin name.
    name: String,
    /// Offending entry.
    entry: String,
    /// Parse failure.
    detail: String,
  },
  /// An OIDC discovery document is not valid JSON.
  #[error("parse discovery document: {source}")]
  ParseDiscovery {
    /// Underlying parse failure.
    #[source]
    source: JsonError,
  },
  /// An OIDC discovery document is not a JSON object.
  #[error("discovery document is not a JSON object")]
  DiscoveryNotAnObject,
  /// An OIDC discovery document lacks `token_endpoint`.
  #[error("discovery document: missing `token_endpoint`")]
  DiscoveryMissingTokenEndpoint,
  /// An OIDC discovery document lacks `grant_types_supported`.
  #[error("discovery document: missing `grant_types_supported`")]
  DiscoveryMissingGrantTypes,
  /// An OIDC discovery document lists no supported grant type.
  #[error("discovery document: no supported grant type (need `authorization_code` or `client_credentials`)")]
  DiscoveryNoSupportedGrantType,
  /// An `OpenAPI` document is not valid JSON.
  #[error("parse openapi document: {source}")]
  ParseOpenapi {
    /// Underlying parse failure.
    #[source]
    source: JsonError,
  },
  /// An `OpenAPI` document has no `components.securitySchemes`.
  #[error("openapi document: no `components.securitySchemes`")]
  OpenapiNoSchemes,
  /// One file claims one env name for two providers.
  #[error("{}: providers `{previous}` and `{provider}` both claim `{env}`", file.display())]
  ClaimConflict {
    /// File carrying the conflict.
    file: PathBuf,
    /// First provider claiming the name.
    previous: String,
    /// Second provider claiming the name.
    provider: String,
    /// Claimed env name.
    env: String,
  },
  /// A registry host entry does not parse.
  #[error("{}: {kind} `{name}`: bad host `{host}`: {detail}", file.display())]
  BadHost {
    /// File carrying the bad host.
    file: PathBuf,
    /// Entry kind (`provider` or `name`).
    kind: String,
    /// Entry name.
    name: String,
    /// Offending host.
    host: String,
    /// Parse failure.
    detail: String,
  },
  /// A registry decoy template does not compile.
  #[error("{}: {kind} `{name}`: bad pattern `{pattern}`: {detail}", file.display())]
  BadRegistryPattern {
    /// File carrying the bad pattern.
    file: PathBuf,
    /// Entry kind (`provider` or `name`).
    kind: String,
    /// Entry name.
    name: String,
    /// Offending pattern.
    pattern: String,
    /// Validation failure.
    detail: String,
  },
  /// A `contains` entry is empty.
  #[error("{}: provider `{provider}`: `contains` entries must not be empty", file.display())]
  EmptyContains {
    /// File carrying the bad entry.
    file: PathBuf,
    /// Provider name.
    provider: String,
  },
  /// A `contains` entry has no `pattern` to select.
  #[error("{}: provider `{provider}`: `contains` needs a `pattern`", file.display())]
  ContainsNeedsPattern {
    /// File carrying the bad entry.
    file: PathBuf,
    /// Provider name.
    provider: String,
  },
  /// A `send` placement or a signing signature placement is not one field.
  #[error("{}: {kind} `{name}`: {detail}", file.display())]
  BadCredentialPlace {
    /// File carrying the bad placement.
    file: PathBuf,
    /// Entry kind (`provider` or `name`).
    kind: String,
    /// Entry name.
    name: String,
    /// What is wrong with the placement.
    detail: String,
  },
  /// A signing secret still grants hosts after the layers merge.
  #[error("{}: `{name}`: signing secret declares hosts", file.display())]
  SigningHasHosts {
    /// File that produced the merged entry.
    file: PathBuf,
    /// Env name.
    name: String,
  },
  /// A signing secret also declares a wire placement for its own value.
  #[error("{}: `{name}`: signing secret also declares `send`", file.display())]
  SigningDeclaresSend {
    /// File that produced the merged entry.
    file: PathBuf,
    /// Env name.
    name: String,
  },
  /// `send` names a wire placement for a name that grants no host.
  #[error("{}: `{name}`: `send` declares a wire placement but the entry grants no host", file.display())]
  SendWithoutHosts {
    /// File that produced the merged entry.
    file: PathBuf,
    /// Env name.
    name: String,
  },
  /// An `oauth2` URL does not parse.
  #[error("{origin}: `{name}`: {source}")]
  BadOAuthUrl {
    /// Config origin.
    origin: String,
    /// Entry name.
    name: String,
    /// Why the URL is unusable.
    #[source]
    source: Box<Error>,
  },
  /// An `authorization_code` flow lacks its `authorize_url`.
  #[error("{origin}: `{name}`: `authorization_code` flow needs an `authorize_url`")]
  FlowNeedsAuthorize {
    /// Config origin.
    origin: String,
    /// Entry name.
    name: String,
  },
  /// A `token_fields` entry is empty.
  #[error("{origin}: `{name}`: `token_fields` entries must not be empty")]
  EmptyTokenField {
    /// Config origin.
    origin: String,
    /// Entry name.
    name: String,
  },
  /// A `token_fields` entry repeats.
  #[error("{origin}: `{name}`: duplicate `token_fields` entry `{field}`")]
  DuplicateTokenField {
    /// Config origin.
    origin: String,
    /// Entry name.
    name: String,
    /// Repeated field.
    field: String,
  },
  /// An `oauth2` URL does not parse.
  #[error("bad oauth2 url `{url}`: {source}")]
  BadUrlParse {
    /// Offending URL.
    url: String,
    /// Underlying parse failure.
    #[source]
    source: UrlError,
  },
  /// An `oauth2` URL carries no host.
  #[error("bad oauth2 url `{url}`: empty host")]
  BadUrlHost {
    /// Offending URL.
    url: String,
  },
  /// A file carries `tools` as something other than a table.
  #[error("{}: `tools` must be a table", path.display())]
  ToolsNotTable {
    /// File carrying the bad `tools` value.
    path: PathBuf,
  },
  /// A `[tools]` entry does not deserialize.
  #[error("{}: tool `{name}`: {source}", path.display())]
  BadTool {
    /// File carrying the bad tool.
    path: PathBuf,
    /// Tool name.
    name: String,
    /// Underlying parse failure.
    #[source]
    source: Box<TomlError>,
  },
  /// A profile cookie's parent is not a string.
  #[error("{}: `[profile] parent` must be a string", path.display())]
  ProfileParentNotString {
    /// Cookie carrying the bad parent.
    path: PathBuf,
  },
  /// The shared base profile names a parent.
  #[error("{}: the shared base profile takes no parent", path.display())]
  SharedProfileParent {
    /// Cookie carrying the parent.
    path: PathBuf,
  },
  /// A profile parent is not a plain directory name.
  #[error("{}: parent `{parent}` is not a plain directory name", path.display())]
  BadProfileParent {
    /// Cookie carrying the bad parent.
    path: PathBuf,
    /// Offending parent.
    parent: String,
  },
  /// A selected profile is not a plain directory name.
  #[error("profile `{name}` is not a plain directory name")]
  BadProfileName {
    /// Offending profile.
    name: String,
  },
  /// Profile inheritance cycles.
  #[error("profile inheritance cycle through `{parent}`")]
  ProfileCycle {
    /// Offending parent.
    parent: String,
  },
  /// A profile parent no layer holds.
  #[error("profile `{name}` inherits `{parent}`, which no layer holds")]
  ProfileParentMissing {
    /// Child profile.
    name: String,
    /// Missing parent.
    parent: String,
  },
  /// A postgres rule states its upstream trust outside the libpq URL.
  #[error("rule `{label}`: postgres states upstream trust in its libpq URL (`sslrootcert`), never in the rule table")]
  PostgresTrust {
    /// Rule label.
    label: String,
  },
  /// A redis rule states its upstream identity outside the connection string.
  #[error("rule `{label}`: redis states the upstream identity in its connection string (`sslcert`/`sslkey`), never in the rule table")]
  RedisIdentity {
    /// Rule label.
    label: String,
  },
  /// A redis rule states its upstream trust outside the connection string.
  #[error("rule `{label}`: redis states upstream trust in its connection string (`sslrootcert`), never in the rule table")]
  RedisTrust {
    /// Rule label.
    label: String,
  },
  /// An SMTP connection string, identity row, or trust row was rejected.
  #[error(transparent)]
  Smtp(#[from] arkham_smtp::Error),
  /// An LDAP connection string, identity row, or trust row was rejected.
  #[error(transparent)]
  Ldap(#[from] arkham_ldap::Error),
  /// A NATS connection string, or the pair of them, does not parse.
  #[error("rule `{label}`: {source}")]
  NatsScope {
    /// Rule label.
    label: String,
    /// Parse failure.
    #[source]
    source: NatsUriError,
  },
  /// A NATS rule states its upstream identity outside the connection string.
  #[error("rule `{label}`: nats states the upstream identity in its connection string (`sslcert`/`sslkey`), never in the rule table")]
  NatsIdentity {
    /// Rule label.
    label: String,
  },
  /// A NATS rule states its upstream trust outside the connection string.
  #[error("rule `{label}`: nats states upstream trust in its connection string (`sslrootcert`), never in the rule table")]
  NatsTrust {
    /// Rule label.
    label: String,
  },
  /// Two NATS grants share a fake host and port but not the dial or guest TLS.
  #[error("rules `{previous}` and `{label}` share nats endpoint `{host}:{port}` with different upstream or guest tls")]
  NatsSharedEndpoint {
    /// The grant already collected for this endpoint.
    previous: String,
    /// The grant that disagreed.
    label: String,
    /// Shared fake host.
    host: String,
    /// Shared fake port.
    port: u16,
  },
  /// An AMQP rule states its upstream identity outside the connection string.
  #[error("rule `{label}`: amqp states the upstream identity in its connection string (`sslcert`/`sslkey`), never in the rule table")]
  AmqpIdentity {
    /// Rule label.
    label: String,
  },
  /// An AMQP rule states its upstream trust outside the connection string.
  #[error("rule `{label}`: amqp states upstream trust in its connection string (`sslrootcert`), never in the rule table")]
  AmqpTrust {
    /// Rule label.
    label: String,
  },
  /// An ssh rule mixes `ssh://` entries with other schemes.
  #[error("rule `{label}`: ssh entries cannot mix with other schemes in one rule")]
  SshMixedSchemes {
    /// Rule label.
    label: String,
  },
  /// An `ssh` table sits on a rule whose allow entries are not ssh: the
  /// table would silently never apply, so resolution fails closed.
  #[error("rule `{label}`: ssh config on a rule with no ssh entry")]
  SshMisplaced {
    /// Rule label.
    label: String,
  },
  /// An ssh rule states a `value`, which nothing would swap.
  #[error("rule `{label}`: an ssh rule states no `value`; its secret is key material in the `ssh` config")]
  SshValue {
    /// Rule label.
    label: String,
  },
  /// An ssh entry carries `tls` config, which only endpoint entries take.
  #[error("rule `{label}`: ssh entry `{entry}` states no `tls` config; its trust is pinned host keys")]
  SshTls {
    /// Rule label.
    label: String,
    /// Offending entry.
    entry: String,
  },
  /// An ssh entry lacks its key material.
  #[error("rule `{label}`: ssh entry `{entry}`: {detail}")]
  SshIdentity {
    /// Rule label.
    label: String,
    /// Offending entry.
    entry: String,
    /// What is missing.
    detail: String,
  },
  /// An `ssh` entry names an `allow` entry the rule does not grant.
  #[error("rule `{label}`: ssh config names entry `{key}` the rule does not allow")]
  SshUnknownEntry {
    /// Rule label.
    label: String,
    /// Offending key.
    key: String,
  },
  /// The in-repo reference samples fail to serialize.
  #[error("serializing the reference samples: {source}")]
  SerializeSamples {
    /// Underlying serialization failure.
    #[source]
    source: TomlSerializeError,
  },
  /// A source path cannot identify a context.
  #[error("source path `{}` {fault}", path.display())]
  ContextPathInvalid {
    /// Path the adapter passed.
    path: PathBuf,
    /// Why the path was rejected.
    #[source]
    fault: PathFault,
  },
  /// A context name cannot become a label.
  #[error("context `{name}` in `{}` on {protocol} {fault}", path.display())]
  ContextNameInvalid {
    /// Path the adapter passed.
    path: PathBuf,
    /// Protocol of the context.
    protocol: AmbientProtocol,
    /// Original name.
    name: String,
    /// Why the name was rejected.
    #[source]
    fault: NameFault,
  },
  /// Two different contexts share a label.
  #[error(transparent)]
  ContextCollision(Box<crate::context::ContextCollision>),
  /// Two contexts present the same host, port, and decoy bytes.
  #[error(transparent)]
  AmbiguousContexts(Box<crate::context::AmbiguousContexts>),
  /// A presented destination host is empty after trimming.
  #[error("wire host is empty")]
  WireHostEmpty,
}
