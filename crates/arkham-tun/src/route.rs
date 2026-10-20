//! Policy routing via netlink (no `ip` CLI: the runtime image ships no
//! iproute2).

use std::net::Ipv4Addr;

use futures_util::TryStreamExt as _;
use rtnetlink::packet_route::rule::RuleAction;
use rtnetlink::packet_route::{
  AddressFamily,
  route::{RouteAttribute, RouteMessage},
  rule::{RuleAttribute, RuleMessage},
};

use crate::Error;
use crate::tun::FWMARK;

/// Priorities of our fib rules: marked upstream bypasses to main first,
/// everything else falls into the capture table.
const RULE_PREF_BYPASS: u32 = 100;
const RULE_PREF_CAPTURE: u32 = 200;
/// Main routing table id.
pub(super) const TABLE_MAIN: u8 = 254;

/// One capture-table route: `dst/plen dev oif`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoutePlan {
  pub dst: Option<(Ipv4Addr, u8)>,
  pub oif: u32,
}

/// One fib rule: `pref -> table`, optionally only for marked packets.
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
  #[cfg(test)]
  DelRoute {
    table: u8,
    plan: RoutePlan,
  },
}

pub(super) fn netlink() -> Result<rtnetlink::Handle, Error> {
  let (conn, handle, _) = rtnetlink::new_connection().map_err(|err| Error::Netlink { origin: err })?;
  tokio::spawn(conn);
  Ok(handle)
}

pub(super) async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32, Error> {
  let mut links = handle.link().get().match_name(name.to_string()).execute();
  let msg = links
    .try_next()
    .await
    .map_err(|err| Error::LinkGet {
      name: name.to_string(),
      origin: err,
    })?
    .ok_or_else(|| Error::InterfaceNotFound { name: name.to_string() })?;
  Ok(msg.header.index)
}

/// Table id of a route message (extended `Table` NLA wins over the header).
fn route_table(msg: &RouteMessage) -> u32 {
  msg
    .attributes
    .iter()
    .find_map(|nla| match nla {
      RouteAttribute::Table(id) => Some(*id),
      _ => None,
    })
    .unwrap_or(u32::from(msg.header.table))
}

/// List all routes (used by `RouteGuard` cleanup).
async fn list_routes(handle: &rtnetlink::Handle) -> Result<Vec<RouteMessage>, Error> {
  handle
    .route()
    .get(RouteMessage::default())
    .execute()
    .try_collect()
    .await
    .map_err(|err| Error::RouteList { origin: err })
}

/// Capture-table routes (pure, tested): everything except loopback goes
/// through the TUN — LAN included, secrets live there too. Non-granted
/// traffic splices through byte-identical; opt-out exemptions are a
/// separate mechanism, not a hardcoded RFC1918 bypass.
pub(crate) fn capture_routes(tun: u32, lo: u32) -> Vec<RoutePlan> {
  vec![
    RoutePlan { dst: None, oif: tun },
    RoutePlan {
      // Network, not LOCALHOST: host bits in a prefix are EINVAL in the kernel.
      dst: Some((Ipv4Addr::new(127, 0, 0, 0), 8)),
      oif: lo,
    },
  ]
}

/// Fib rules (pure, tested): marked upstream → main, rest → capture table.
pub(crate) fn capture_rules(table: u8) -> Vec<RulePlan> {
  vec![
    RulePlan {
      pref: RULE_PREF_BYPASS,
      fwmark: Some(FWMARK),
      table: TABLE_MAIN,
    },
    RulePlan {
      pref: RULE_PREF_CAPTURE,
      fwmark: None,
      table,
    },
  ]
}

/// Undo for [`capture_routes`] + [`capture_rules`].
pub(crate) fn capture_undos(table: u8) -> Vec<Undo> {
  // Drop iterates in reverse: the capture rule goes first so traffic falls
  // back to main even if the table flush fails, then the table, then the
  // bypass rule.
  vec![
    Undo::DelRulePref(RULE_PREF_BYPASS),
    Undo::FlushTable(table),
    Undo::DelRulePref(RULE_PREF_CAPTURE),
  ]
}

fn route_message(table: u8, plan: &RoutePlan) -> RouteMessage {
  let mut builder = rtnetlink::RouteMessageBuilder::<Ipv4Addr>::new();
  if let Some((dst, len)) = plan.dst {
    builder = builder.destination_prefix(dst, len);
  }
  builder.output_interface(plan.oif).table_id(u32::from(table)).build()
}

pub(super) async fn add_route(handle: &rtnetlink::Handle, table: u8, plan: &RoutePlan) -> Result<(), Error> {
  handle
    .route()
    .add(route_message(table, plan))
    .replace()
    .execute()
    .await
    .map_err(|err| Error::RouteAdd { origin: err })?;
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
    .map_err(|err| Error::RuleAdd { origin: err })?;
  Ok(())
}

/// Priority of a fib rule message, if set.
fn rule_priority(msg: &RuleMessage) -> Option<u32> {
  msg.attributes.iter().find_map(|nla| match nla {
    RuleAttribute::Priority(pref) => Some(*pref),
    _ => None,
  })
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
    if rule_priority(&msg) == Some(pref) {
      handle
        .rule()
        .del(msg)
        .execute()
        .await
        .map_err(|err| Error::RuleDel { origin: err })?;
    }
  }
  Ok(())
}

async fn flush_table(handle: &rtnetlink::Handle, table: u8) -> Result<(), Error> {
  for msg in list_routes(handle).await? {
    if msg.header.address_family == AddressFamily::Inet && route_table(&msg) == u32::from(table) {
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
    Undo::FlushTable(table) => flush_table(handle, *table).await,
    Undo::DelRulePref(pref) => del_rule_pref(handle, *pref).await,
    #[cfg(test)]
    Undo::DelRoute { table, plan } => {
      handle
        .route()
        .del(route_message(*table, plan))
        .execute()
        .await
        .map_err(|err| Error::RouteDel { origin: err })?;
      Ok(())
    }
  }
}

/// Removes routes/rules on drop (best-effort). Netlink is async, so cleanup
/// runs on a throwaway thread+runtime — works inside runtimes and during
/// unwind. Stale capture routes would blackhole traffic after exit, so
/// cleanup must run.
pub(crate) struct RouteGuard {
  undos: Vec<Undo>,
}

impl RouteGuard {
  pub(super) fn new(undos: Vec<Undo>) -> Self {
    Self { undos }
  }
}

impl Drop for RouteGuard {
  fn drop(&mut self) {
    let undos = std::mem::take(&mut self.undos);
    let _ = std::thread::spawn(move || {
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
          if let Err(err) = apply_undo(&handle, undo).await {
            tracing::error!(?err, ?undo, "route cleanup undo failed; capture routes may be stale");
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
  fn capture_plan_routes_rules_and_undos() {
    assert_eq!(
      capture_routes(7, 1),
      vec![
        RoutePlan { dst: None, oif: 7 },
        RoutePlan {
          dst: Some((Ipv4Addr::new(127, 0, 0, 0), 8)),
          oif: 1
        },
      ]
    );
    assert_eq!(
      capture_rules(100),
      vec![
        RulePlan {
          pref: 100,
          fwmark: Some(FWMARK),
          table: TABLE_MAIN
        },
        RulePlan {
          pref: 200,
          fwmark: None,
          table: 100
        },
      ]
    );
    assert_eq!(
      capture_undos(100),
      vec![Undo::DelRulePref(100), Undo::FlushTable(100), Undo::DelRulePref(200)]
    );
  }
}
