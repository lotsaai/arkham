//! Map access: turning a captured flow's local 4-tuple back into the original
//! destination the client asked for.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::Error;
use crate::{FlowKey, FlowRecord, OrigDst};
use aya::maps::MapError;
use aya::{
  Ebpf,
  maps::{HashMap, MapData},
};

/// `IPPROTO_TCP`, matching the programs.
pub(crate) const PROTO_TCP: u8 = 6;
/// `IPPROTO_UDP`, matching the programs.
pub(crate) const PROTO_UDP: u8 = 17;

/// Read-only views of the TCP capture maps.
///
/// `MapData` is reference-counted, so cloning the tables shares the maps.
///
/// The programs declare these maps as `LRU_HASH`, but aya exposes LRU and plain
/// hash maps through the same userspace type: the distinction only affects
/// kernel-side eviction.
#[derive(Clone)]
pub(crate) struct FlowTables {
  flows: Arc<HashMap<MapData, FlowKey, FlowRecord>>,
  orig: Arc<HashMap<MapData, u64, OrigDst>>,
}

impl FlowTables {
  /// Take ownership of the `FLOW` and `ORIG_DST` maps out of a loaded object.
  pub(crate) fn from_bpf(bpf: &mut Ebpf) -> Result<Self, Error> {
    let flows = bpf.take_map("FLOW").ok_or(Error::MapMissing { name: "FLOW" })?;
    let orig = bpf.take_map("ORIG_DST").ok_or(Error::MapMissing { name: "ORIG_DST" })?;
    Ok(Self {
      flows: Arc::new(
        flows
          .try_into()
          .map_err(|err| Error::UnexpectedMapType { name: "FLOW", origin: err })?,
      ),
      orig: Arc::new(orig.try_into().map_err(|err| Error::UnexpectedMapType {
        name: "ORIG_DST",
        origin: err,
      })?),
    })
  }

  /// Original destination for a captured flow whose peer address is `peer`,
  /// which must have been captured for `proto`.
  ///
  /// The client's socket was rewritten to connect to our loopback listener, so
  /// the server leg sees that loopback address as its peer — exactly the key
  /// the egress hook recorded. `None` means the flow was never redirected (or
  /// the LRU entry aged out); callers close quietly rather than guess.
  ///
  /// The protocol check rejects an entry that does not belong to this leg.
  pub(crate) fn original(&self, peer: SocketAddr, proto: u8) -> Result<Option<CapturedFlow>, Error> {
    let key = FlowKey::from_peer(peer);
    let record = match self.flows.get(&key, 0) {
      Ok(record) => record,
      // A missing key is the ordinary "not captured" case, not an error.
      Err(MapError::KeyNotFound) => return Ok(None),
      Err(err) => return Err(Error::ReadFlow { origin: err }),
    };
    match self.orig.get(&record.cookie, 0) {
      Ok(orig) if orig.proto == proto => Ok(Some(CapturedFlow {
        cookie: record.cookie,
        destination: orig.socket_addr(),
        cgroup_id: record.cgroup_id,
      })),
      // Either the entry aged out of the LRU, or the local port has been
      // reused by the other protocol: both mean "not this flow".
      Ok(_) | Err(MapError::KeyNotFound) => Ok(None),
      Err(err) => Err(Error::ReadOrigDst { origin: err }),
    }
  }
}

/// Cgroup a captured flow may still be served as.
///
/// `recorded` is the id stored when the socket connected. `live` is the
/// cgroup of the socket being accepted. A close deletes the map entry, so
/// accept then sees `0`. A reused source port that still has the old entry
/// carries the previous project only when the live socket is that same cgroup.
#[must_use]
pub(crate) fn retained_cgroup(recorded: u64, live: u64) -> Option<u64> {
  if recorded == 0 || live == 0 || recorded != live {
    None
  } else {
    Some(recorded)
  }
}

/// A redirected flow: where the client was going, and which cgroup it ran in.
pub(crate) struct CapturedFlow {
  pub cookie: u64,
  /// Original destination, before the hook rewrote it.
  pub destination: SocketAddr,
  /// Cgroup id of the connecting process.
  pub cgroup_id: u64,
}

#[cfg(test)]
mod tests {
  use super::retained_cgroup;

  #[test]
  fn a_reused_port_after_close_does_not_inherit_the_old_project() {
    assert_eq!(retained_cgroup(0, 22), None);
    assert_eq!(retained_cgroup(11, 22), None);
    assert_eq!(retained_cgroup(11, 0), None);
    assert_eq!(retained_cgroup(11, 11), Some(11));
  }
}
