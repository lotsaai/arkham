//! WASM rewrite-plugin host: grant-gated component execution.
//!
//! Plugins rewrite message heads, trailer blocks, and body chunks around the
//! in-core value swap. The host owns grants, the relay, secrets, and
//! redaction; a plugin only ever sees wire content. Every guest failure —
//! guest `Err`, trap, out of fuel, epoch deadline — fails the connection
//! closed: the hook returns [`Verdict::Close`] and the relay drops it.

mod bindings;
mod error;

use arkham_config::grants::{Scheme, uri_match};
use arkham_config::plugins::{PluginDirection, ResolvedPlugin};
pub use error::Error;
use std::fmt;
use std::pin::Pin;
use std::time::Duration;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// Boxed sendable future for [`RewriteHook`] methods.
///
/// One local line instead of a `futures` dependency.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One HTTP header: name plus raw value bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
  /// Header field name, verbatim case.
  pub name: String,
  /// Raw field value bytes.
  pub value: Vec<u8>,
}

/// One message head, post value-swap.
#[derive(Debug, Clone)]
pub enum Head {
  /// Request head: method, request target, and fields.
  Request {
    /// Request method token.
    method: String,
    /// Request-line target (path plus query).
    path_with_query: String,
    /// Message fields.
    headers: Vec<Header>,
  },
  /// Response head: status code and fields.
  Response {
    /// Numeric status code.
    status: u16,
    /// Message fields.
    headers: Vec<Header>,
  },
}

/// Hook outcome: keep the connection or drop it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
  /// Continue the connection with the rewritten content.
  Continue,
  /// Drop the connection; the relay never forwards the latched chunk.
  Close,
}

/// Universal stage interface for one rewrite direction of one connection.
///
/// The in-core value swap is stage 0; a plugin hook runs after it. This
/// trait is the plugin boundary: the relay depends on the interface, never
/// on the wasmtime-backed implementation, so guests stay boxed behind the
/// sandbox host.
pub trait RewriteHook: Send {
  /// Rewrite one message head in place.
  fn rewrite_head<'a>(&'a mut self, head: &'a mut Head) -> BoxFuture<'a, Verdict>;
  /// Rewrite one trailer block in place; the list replaces the block wholesale.
  fn rewrite_trailers<'a>(&'a mut self, headers: &'a mut Vec<Header>) -> BoxFuture<'a, Verdict>;
  /// Rewrite one body region in place; `eof` marks the final region, on
  /// which the plugin must return everything it holds back.
  fn rewrite_chunk<'a>(&'a mut self, data: &'a mut Vec<u8>, eof: bool) -> BoxFuture<'a, Verdict>;
}

/// Which connection leg a hook rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
  /// Client-to-server leg.
  Request,
  /// Server-to-client leg.
  Response,
}

/// Fuel per guest call; a plugin doing chunked signing burns a fraction of this.
const FUEL_PER_CALL: u64 = 50_000_000;
/// Epoch deadline in [`EPOCH_TICK_MS`] ticks (~300 ms) per guest call.
const EPOCH_DEADLINE_TICKS: u64 = 3;
/// Epoch tick interval; one shared thread bumps the engine clock this often.
const EPOCH_TICK_MS: u64 = 100;
/// Guest linear-memory cap: plugins buffer in guest memory, never in host code.
const GUEST_MEMORY_BYTES: usize = 64 * 1024 * 1024;
/// Guest table-element cap; the worlds import nothing, so one table suffices.
const GUEST_TABLE_ELEMENTS: usize = 10_000;

/// Per-instance store data: the resource limiter plus a capability-free
/// WASI context. Guest `std` imports WASI interfaces (e.g. `wasi:io/poll`)
/// even though our worlds import nothing; the context grants no env, no
/// args, no preopens, and no stdio, so the sandbox posture is unchanged.
struct PluginStoreData {
  /// Caps guest memory, tables, and instances (sandbox recipe).
  limits: StoreLimits,
  /// Handle table backing WASI resources.
  table: ResourceTable,
  /// Capability-free WASI state.
  wasi: WasiCtx,
}

impl WasiView for PluginStoreData {
  fn ctx(&mut self) -> WasiCtxView<'_> {
    WasiCtxView {
      ctx: &mut self.wasi,
      table: &mut self.table,
    }
  }
}

/// Which rewrite world(s) a component implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorldSupport {
  /// Implements the `request` world only.
  Request,
  /// Implements the `response` world only.
  Response,
  /// Implements both worlds.
  Both,
}

/// One compiled plugin plus its grant metadata.
struct LoadedPlugin {
  /// Config label (`[plugins.<name>]`), log identifier only.
  name: String,
  /// Component compiled once at load.
  component: Component,
  /// Parsed allow entries. Plugin matching reads scheme, host and port, so a
  /// database entry just scopes the plugin to that endpoint.
  allow: Vec<arkham_config::grants::EndpointScope>,
  /// Direction gate from config.
  direction: PluginDirection,
  /// Probed world support.
  support: WorldSupport,
}

/// Grant-gated plugin set: shared engine, components compiled once.
///
/// Write-once for process lifetime; selection hands out fresh per-connection
/// instances with no shared state and no lock across an await.
pub struct Registry {
  /// Shared engine: one configuration, epoch clock, and code cache.
  engine: Engine,
  /// Loaded plugins in config order; first grant match wins.
  plugins: Vec<LoadedPlugin>,
}

impl fmt::Debug for Registry {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Registry")
      .field("plugins", &self.plugins.iter().map(|plugin| &plugin.name).collect::<Vec<_>>())
      .finish_non_exhaustive()
  }
}

/// Config direction gate allows this leg.
fn direction_allows(configured: PluginDirection, leg: Direction) -> bool {
  match configured {
    PluginDirection::Both => true,
    PluginDirection::Request => leg == Direction::Request,
    PluginDirection::Response => leg == Direction::Response,
  }
}

/// The component implements this leg's world.
fn world_supports(support: WorldSupport, leg: Direction) -> bool {
  match support {
    WorldSupport::Both => true,
    WorldSupport::Request => leg == Direction::Request,
    WorldSupport::Response => leg == Direction::Response,
  }
}

/// Fresh store with fuel-independent sandbox limits, fuel, and epoch armed.
///
/// Per-call `arm` refreshes fuel and deadline before every guest call.
///
/// # Errors
///
/// Returns an error when the engine rejects the initial fuel allocation.
fn scratch_store(engine: &Engine) -> Result<Store<PluginStoreData>, Error> {
  let limits = StoreLimitsBuilder::new()
    .memory_size(GUEST_MEMORY_BYTES)
    .table_elements(GUEST_TABLE_ELEMENTS)
    // The guest plus one adapter instance per WASI interface its std
    // imports; the worlds themselves import nothing.
    .instances(8)
    .tables(8)
    .build();
  let mut store = Store::new(
    engine,
    PluginStoreData {
      limits,
      table: ResourceTable::new(),
      wasi: WasiCtxBuilder::new().build(),
    },
  );
  store.limiter(|data| &mut data.limits);
  // Instantiation itself burns fuel and runs under the epoch: arm both
  // here; per-call `arm` refreshes them before every guest call.
  store.set_fuel(FUEL_PER_CALL).map_err(|origin| Error::FuelArm { origin })?;
  store.set_epoch_deadline(EPOCH_DEADLINE_TICKS);
  Ok(store)
}

/// Probe which rewrite world(s) a component implements.
///
/// Instantiation type-checks exports; a component implementing neither world
/// fails load.
///
/// # Errors
///
/// Returns an error when the component implements neither rewrite world.
fn probe_world(engine: &Engine, component: &Component, name: &str) -> Result<WorldSupport, Error> {
  let mut linker = Linker::new(engine);
  // Sync flavor: the probe only instantiates (typechecks exports), never
  // calls, so it must not require an async store. Running instances use
  // the async linker in `ensure_running`.
  wasmtime_wasi::p2::add_to_linker_sync(&mut linker).map_err(|err| Error::WasiLinker {
    name: name.to_string(),
    origin: err,
  })?;
  let request = bindings::request::Request::instantiate(&mut scratch_store(engine)?, component, &linker);
  let response = bindings::response::Response::instantiate(&mut scratch_store(engine)?, component, &linker);
  match (&request, &response) {
    (Ok(_), Ok(_)) => Ok(WorldSupport::Both),
    (Ok(_), Err(_)) => Ok(WorldSupport::Request),
    (Err(_), Ok(_)) => Ok(WorldSupport::Response),
    (Err(request_err), Err(response_err)) => Err(Error::NeitherWorld {
      name: name.to_string(),
      request: format!("{request_err:#}"),
      response: format!("{response_err:#}"),
    }),
  }
}

impl Registry {
  /// Compile every configured plugin and probe its worlds.
  ///
  /// A missing file, a component that fails to compile, or a component
  /// implementing neither world fails startup: fail closed.
  ///
  /// # Errors
  ///
  /// Returns an error when any plugin cannot be read, compiled, or probed.
  pub fn load(plugins: &[ResolvedPlugin]) -> Result<Self, Error> {
    let mut config = Config::new();
    config.epoch_interruption(true);
    config.consume_fuel(true);
    let engine = Engine::new(&config).map_err(|err| Error::Engine { origin: err })?;
    let mut loaded = Vec::with_capacity(plugins.len());
    for plugin in plugins {
      let component = Component::from_file(&engine, &plugin.path).map_err(|err| Error::LoadComponent {
        name: plugin.name.clone(),
        path: plugin.path.clone(),
        origin: err,
      })?;
      let support = probe_world(&engine, &component, &plugin.name)?;
      loaded.push(LoadedPlugin {
        name: plugin.name.clone(),
        component,
        allow: plugin.allow.clone(),
        direction: plugin.direction,
        support,
      });
    }
    if !loaded.is_empty() {
      let epoch_engine = engine.clone();
      std::thread::spawn(move || {
        loop {
          std::thread::sleep(Duration::from_millis(EPOCH_TICK_MS));
          epoch_engine.increment_epoch();
        }
      });
    }
    Ok(Self { engine, plugins: loaded })
  }

  /// First plugin whose grants, direction gate, and world support match this
  /// leg, as a fresh per-connection hook.
  ///
  /// Each selection instantiates a new guest on first use: per-connection
  /// state, nothing shared.
  #[must_use]
  pub fn select(&self, scheme: Scheme, host: &str, port: u16, leg: Direction) -> Option<Box<dyn RewriteHook>> {
    self
      .plugins
      .iter()
      .find(|plugin| {
        uri_match(&plugin.allow, scheme, host, port) && direction_allows(plugin.direction, leg) && world_supports(plugin.support, leg)
      })
      .map(|plugin| {
        Box::new(PluginInstance::new(
          plugin.name.clone(),
          self.engine.clone(),
          plugin.component.clone(),
          leg,
        )) as Box<dyn RewriteHook>
      })
  }
}

/// Which world this instance speaks; fixed at selection time.
type RunningRequest = bindings::request::Request;
/// Response-world bindings for the running instance.
type RunningResponse = bindings::response::Response;

/// Live guest: store plus instantiated world bindings.
enum Running {
  /// Request-world guest.
  Request {
    /// Per-connection store: limits, fuel, and epoch deadline.
    store: Store<PluginStoreData>,
    /// Instantiated request-world exports.
    instance: RunningRequest,
  },
  /// Response-world guest.
  Response {
    /// Per-connection store: limits, fuel, and epoch deadline.
    store: Store<PluginStoreData>,
    /// Instantiated response-world exports.
    instance: RunningResponse,
  },
}

/// Per-connection plugin hook: one store, one instance, no shared state.
struct PluginInstance {
  /// Config label, log identifier only; never logged with values.
  name: String,
  /// Engine clone for per-connection stores.
  engine: Engine,
  /// Precompiled component; instantiation is per connection.
  component: Component,
  /// Leg (and world) selected for this connection.
  leg: Direction,
  /// Lazily instantiated on the first async hook call.
  running: Option<Running>,
}

impl fmt::Debug for PluginInstance {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("PluginInstance").field("name", &self.name).finish_non_exhaustive()
  }
}

/// Fail closed: log the plugin name only, never wire values.
fn fail_closed(name: &str) -> Verdict {
  tracing::warn!(plugin = name, "plugin call failed; failing closed");
  Verdict::Close
}

impl PluginInstance {
  /// One uninstantiated hook; the guest starts on the first async call.
  fn new(name: String, engine: Engine, component: Component, leg: Direction) -> Self {
    Self {
      name,
      engine,
      component,
      leg,
      running: None,
    }
  }

  /// Instantiate the guest on first use; later calls reuse it.
  ///
  /// # Errors
  ///
  /// Returns an error when the component does not implement the selected
  /// leg's world or instantiation traps.
  async fn ensure_running(&mut self) -> Result<(), Error> {
    if self.running.is_some() {
      return Ok(());
    }
    let mut store = scratch_store(&self.engine)?;
    let mut linker = Linker::new(&self.engine);
    wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(|err| Error::WasiLinker {
      name: self.name.clone(),
      origin: err,
    })?;
    let running = match self.leg {
      Direction::Request => {
        let instance = RunningRequest::instantiate_async(&mut store, &self.component, &linker)
          .await
          .map_err(|err| Error::RequestInstantiate {
            name: self.name.clone(),
            origin: err,
          })?;
        Running::Request { store, instance }
      }
      Direction::Response => {
        let instance = RunningResponse::instantiate_async(&mut store, &self.component, &linker)
          .await
          .map_err(|err| Error::ResponseInstantiate {
            name: self.name.clone(),
            origin: err,
          })?;
        Running::Response { store, instance }
      }
    };
    self.running = Some(running);
    Ok(())
  }
  /// Arm per-call budgets: fresh fuel and epoch deadline every call.
  /// `false` means fuel metering is off, which must never happen; the
  /// caller fails the connection closed.
  fn arm(store: &mut Store<PluginStoreData>) -> bool {
    if store.set_fuel(FUEL_PER_CALL).is_err() {
      return false;
    }
    store.set_epoch_deadline(EPOCH_DEADLINE_TICKS);
    true
  }
}

fn header_from_request(header: &bindings::request::arkham::rewrite::types::Header) -> Header {
  Header {
    name: header.name.clone(),
    value: header.value.clone(),
  }
}

fn header_into_request(header: &Header) -> bindings::request::arkham::rewrite::types::Header {
  bindings::request::arkham::rewrite::types::Header {
    name: header.name.clone(),
    value: header.value.clone(),
  }
}

fn header_from_response(header: &bindings::response::arkham::rewrite::types::Header) -> Header {
  Header {
    name: header.name.clone(),
    value: header.value.clone(),
  }
}

fn header_into_response(header: &Header) -> bindings::response::arkham::rewrite::types::Header {
  bindings::response::arkham::rewrite::types::Header {
    name: header.name.clone(),
    value: header.value.clone(),
  }
}

impl RewriteHook for PluginInstance {
  fn rewrite_head<'a>(&'a mut self, head: &'a mut Head) -> BoxFuture<'a, Verdict> {
    Box::pin(async move {
      let name = self.name.clone();
      if self.ensure_running().await.is_err() {
        return fail_closed(&name);
      }
      // The slot was filled just above; an empty read still fails closed
      // rather than panicking.
      let Some(running) = self.running.as_mut() else {
        return fail_closed(&name);
      };
      match (running, &mut *head) {
        (
          Running::Request { store, instance },
          Head::Request {
            method,
            path_with_query,
            headers,
          },
        ) => {
          if !Self::arm(store) {
            return fail_closed(&name);
          }
          let guest_head = bindings::request::arkham::rewrite::types::RequestHead {
            method: method.clone(),
            path_with_query: path_with_query.clone(),
            headers: headers.iter().map(header_into_request).collect(),
          };
          match instance.call_rewrite_request_head(store, &guest_head).await {
            Ok(Ok(new)) => {
              *method = new.method;
              *path_with_query = new.path_with_query;
              *headers = new.headers.iter().map(header_from_request).collect();
              Verdict::Continue
            }
            Ok(Err(_)) | Err(_) => fail_closed(&name),
          }
        }
        (Running::Response { store, instance }, Head::Response { status, headers }) => {
          if !Self::arm(store) {
            return fail_closed(&name);
          }
          let guest_head = bindings::response::arkham::rewrite::types::ResponseHead {
            status: *status,
            headers: headers.iter().map(header_into_response).collect(),
          };
          match instance.call_rewrite_response_head(store, &guest_head).await {
            Ok(Ok(new)) => {
              *status = new.status;
              *headers = new.headers.iter().map(header_from_response).collect();
              Verdict::Continue
            }
            Ok(Err(_)) | Err(_) => fail_closed(&name),
          }
        }
        _ => fail_closed(&name),
      }
    })
  }

  fn rewrite_trailers<'a>(&'a mut self, headers: &'a mut Vec<Header>) -> BoxFuture<'a, Verdict> {
    Box::pin(async move {
      let name = self.name.clone();
      if self.ensure_running().await.is_err() {
        return fail_closed(&name);
      }
      let Some(running) = self.running.as_mut() else {
        return fail_closed(&name);
      };
      match running {
        Running::Request { store, instance } => {
          if !Self::arm(store) {
            return fail_closed(&name);
          }
          let guest: Vec<bindings::request::arkham::rewrite::types::Header> = headers.iter().map(header_into_request).collect();
          match instance.call_rewrite_request_trailers(store, &guest).await {
            Ok(Ok(new)) => {
              *headers = new.iter().map(header_from_request).collect();
              Verdict::Continue
            }
            Ok(Err(_)) | Err(_) => fail_closed(&name),
          }
        }
        Running::Response { store, instance } => {
          if !Self::arm(store) {
            return fail_closed(&name);
          }
          let guest: Vec<bindings::response::arkham::rewrite::types::Header> = headers.iter().map(header_into_response).collect();
          match instance.call_rewrite_response_trailers(store, &guest).await {
            Ok(Ok(new)) => {
              *headers = new.iter().map(header_from_response).collect();
              Verdict::Continue
            }
            Ok(Err(_)) | Err(_) => fail_closed(&name),
          }
        }
      }
    })
  }

  fn rewrite_chunk<'a>(&'a mut self, data: &'a mut Vec<u8>, eof: bool) -> BoxFuture<'a, Verdict> {
    Box::pin(async move {
      let name = self.name.clone();
      if self.ensure_running().await.is_err() {
        return fail_closed(&name);
      }
      let Some(running) = self.running.as_mut() else {
        return fail_closed(&name);
      };
      match running {
        Running::Request { store, instance } => {
          if !Self::arm(store) {
            return fail_closed(&name);
          }
          let guest = bindings::request::arkham::rewrite::types::BodyChunk {
            data: std::mem::take(data),
            eof,
          };
          match instance.call_rewrite_request_chunk(store, &guest).await {
            Ok(Ok(new)) => {
              *data = new;
              Verdict::Continue
            }
            Ok(Err(_)) | Err(_) => fail_closed(&name),
          }
        }
        Running::Response { store, instance } => {
          if !Self::arm(store) {
            return fail_closed(&name);
          }
          let guest = bindings::response::arkham::rewrite::types::BodyChunk {
            data: std::mem::take(data),
            eof,
          };
          match instance.call_rewrite_response_chunk(store, &guest).await {
            Ok(Ok(new)) => {
              *data = new;
              Verdict::Continue
            }
            Ok(Err(_)) | Err(_) => fail_closed(&name),
          }
        }
      }
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use arkham_config::grants::EndpointScope;

  /// Empty load: no components, no epoch thread.
  fn empty_registry() -> Registry {
    Registry::load(&[]).unwrap()
  }

  #[test]
  fn empty_registry_selects_nothing() {
    let registry = empty_registry();
    assert!(registry.select(Scheme::Https, "api.example.com", 443, Direction::Request).is_none());
  }

  #[test]
  fn select_rejects_non_matching_grant() {
    let registry = empty_registry();
    let allow: EndpointScope = "https://other.example.com".parse().unwrap();
    assert!(!uri_match(&[allow], Scheme::Https, "api.example.com", 443));
    assert!(registry.select(Scheme::Https, "api.example.com", 443, Direction::Request).is_none());
  }

  #[test]
  fn select_rejects_wrong_direction() {
    assert!(!direction_allows(PluginDirection::Request, Direction::Response));
    assert!(!direction_allows(PluginDirection::Response, Direction::Request));
    assert!(!world_supports(WorldSupport::Request, Direction::Response));
    assert!(!world_supports(WorldSupport::Response, Direction::Request));
    let registry = empty_registry();
    assert!(
      registry
        .select(Scheme::Https, "api.example.com", 443, Direction::Response)
        .is_none()
    );
  }
}
