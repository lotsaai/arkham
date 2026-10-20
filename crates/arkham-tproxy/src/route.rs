//! Policy routing via netlink (no `ip` CLI: the runtime image ships no
//! iproute2): one fib rule and one local-default route for TPROXY
//! delivery.

use std::mem;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

use crate::Error;

use futures_util::TryStreamExt as _;
use rtnetlink::packet_route::route::{RouteAttribute, RouteMessage, RouteType};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute};
use rtnetlink::{RouteMessageBuilder, packet_route::rule::RuleMessage};

use crate::tproxy::FWMARK;

/// Priorities of the fib rule: captured (marked) packets fall into the
/// local-delivery table. Unmarked traffic never consults it — the OUTPUT
/// nft rule is the only thing that marks, and it already exempts arkham's
/// own sockets, so no bypass rule exists (unlike the TUN shape).
const RULE_PREF_CAPTURE: u32 = 200;

/// One fib rule: `pref -> table`, optionally only marked packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RulePlan {
  pub pref: u32,
  pub fwmark: Option<u32>,
  pub table: u8,
}

/// Teardown operations, executed in reverse order on drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Undo {
  FlushTable(u8),
  DelRulePref(u32),
}

pub(super) fn netlink() -> Result<rtnetlink::Handle, Error> {
  let (conn, handle, _) = rtnetlink::new_connection().map_err(|err| Error::Netlink { origin: err })?;
  tokio::spawn(conn);
  Ok(handle)
}

pub(super) async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32, Error> {
  let mut links = handle.link().get().match_name(name.to_string()).execute();
  match links.try_next().await.map_err(|err| Error::LinkGet {
    name: name.to_string(),
    origin: err,
  })? {
    Some(link) => Ok(link.header.index),
    None => Err(Error::InterfaceNotFound { name: name.to_string() }),
  }
}

/// Fib rule (pure, tested): captured (marked) traffic → local table.
pub(crate) fn proxy_rules(table: u8) -> Vec<RulePlan> {
  vec![RulePlan {
    pref: RULE_PREF_CAPTURE,
    fwmark: Some(FWMARK),
    table,
  }]
}

/// Undo for the rule + local route of [`crate::tproxy::run_tproxy_with`].
pub(crate) fn proxy_undos(table: u8) -> Vec<Undo> {
  vec![Undo::FlushTable(table), Undo::DelRulePref(RULE_PREF_CAPTURE)]
}

pub(super) async fn add_local_route(handle: &rtnetlink::Handle, table: u8, lo_index: u32) -> Result<(), Error> {
  let message = RouteMessageBuilder::<Ipv4Addr>::new()
    .kind(RouteType::Local)
    // `ip route add local ...` implies host scope; the kernel rejects the
    // route with EINVAL when the scope is left as universe.
    .scope(rtnetlink::packet_route::route::RouteScope::Host)
    .output_interface(lo_index)
    .table_id(u32::from(table))
    .build();
  handle
    .route()
    .add(message)
    .replace()
    .execute()
    .await
    .map_err(|err| Error::LocalRouteAdd { origin: err })?;
  Ok(())
}

pub(super) async fn add_rule(handle: &rtnetlink::Handle, plan: &RulePlan) -> Result<(), Error> {
  let mut req = handle.rule().add();
  if let Some(mark) = plan.fwmark {
    req = req.fw_mark(mark);
  }
  req
    .table_id(u32::from(plan.table))
    .priority(plan.pref)
    .action(RuleAction::ToTable)
    .v4()
    .replace()
    .execute()
    .await
    .map_err(|err| Error::RuleAdd {
      pref: plan.pref,
      origin: err,
    })?;
  Ok(())
}

async fn del_rule_pref(handle: &rtnetlink::Handle, pref: u32) -> Result<(), Error> {
  let rules: Vec<RuleMessage> = handle
    .rule()
    .get(rtnetlink::IpVersion::V4)
    .execute()
    .try_collect()
    .await
    .map_err(|err| Error::RuleList { origin: err })?;
  for msg in rules {
    let is_pref = msg
      .attributes
      .iter()
      .any(|attr| matches!(attr, RuleAttribute::Priority(p) if *p == pref));
    if is_pref {
      handle
        .rule()
        .del(msg)
        .execute()
        .await
        .map_err(|err| Error::RuleDel { pref, origin: err })?;
    }
  }
  Ok(())
}

async fn flush_table(handle: &rtnetlink::Handle, table: u8) -> Result<(), Error> {
  let routes: Vec<RouteMessage> = handle
    .route()
    .get(RouteMessage::default())
    .execute()
    .try_collect()
    .await
    .map_err(|err| Error::RouteList { origin: err })?;
  for msg in routes {
    let in_table = msg
      .attributes
      .iter()
      .any(|attr| matches!(attr, RouteAttribute::Table(id) if *id == u32::from(table)));
    if in_table {
      handle
        .route()
        .del(msg)
        .execute()
        .await
        .map_err(|err| Error::RouteDel { origin: err })?;
    }
  }
  Ok(())
}

async fn apply_undo(handle: &rtnetlink::Handle, undo: &Undo) -> Result<(), Error> {
  match undo {
    Undo::DelRulePref(pref) => del_rule_pref(handle, *pref).await,
    Undo::FlushTable(table) => flush_table(handle, *table).await,
  }
}

/// Reverts routes/rules on drop (best-effort). Netlink is async, so cleanup
/// runs on a throwaway thread+runtime — works inside runtimes during
/// unwind. Stale capture routes would blackhole traffic after exit, so
/// cleanup must run.
pub(crate) struct RouteGuard {
  undos: Vec<Undo>,
}

impl RouteGuard {
  pub(crate) fn new(undos: Vec<Undo>) -> Self {
    Self { undos }
  }
}

impl Drop for RouteGuard {
  fn drop(&mut self) {
    let undos = mem::take(&mut self.undos);
    let _ = thread::spawn(move || {
      let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return;
      };
      runtime.block_on(async {
        let handle = match netlink() {
          Ok(handle) => handle,
          Err(err) => {
            tracing::error!(?err, "route cleanup failed: netlink unavailable; capture routes may be stale");
            return;
          }
        };
        for undo in undos.iter().rev() {
          // Bounded: cleanup must never block process exit on a stalled
          // rtnetlink exchange.
          match tokio::time::timeout(Duration::from_secs(5), apply_undo(&handle, undo)).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
              tracing::error!(?err, ?undo, "route cleanup undo failed; capture routes may be stale");
            }
            Err(_) => {
              tracing::error!(?undo, "route cleanup undo timed out; capture routes may be stale");
            }
          }
        }
      });
    })
    .join();
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn proxy_rules_and_undos_plan() {
    assert_eq!(
      proxy_rules(100),
      vec![RulePlan {
        pref: 200,
        fwmark: Some(FWMARK),
        table: 100
      }]
    );
    assert_eq!(proxy_undos(100), vec![Undo::FlushTable(100), Undo::DelRulePref(200)]);
  }
}
