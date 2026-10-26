//! Substitution engine: the shared needle machinery every framing machine
//! is built on — pair eligibility, mint plans, and the scan/replace
//! primitives. Protocol-agnostic by construction; the framing machines
//! that use it live in their protocol verticals.

#[cfg(test)]
pub(crate) mod harness;

#[cfg(test)]
mod fuzz_props;

mod scan;
mod wire;

pub(crate) use super::amqp::machine::Amqp;
pub(crate) use super::http::h2::H2;
pub(crate) use super::http::machine::Http;
pub(crate) use super::ldap::machine::Ldap;
pub(crate) use super::postgres::machine::{GuestOpening, Postgres, read_guest_opening, request_upstream_tls};
pub(crate) use super::redis::machine::Redis;
pub(crate) use super::ssh::legs::{LegKeys, SshLegs, SshLegsFiles, Upstream};
pub(crate) use super::tcp::machine::Raw;

pub(crate) use scan::{
  MAX_MINT_BODY, MintPlan, eligible_pairs, find_crossing, find_new_match, max_tail_size, mint_and_redact, mint_plan_for, minted_pairs,
  needle_prefix_suffix_len, needle_safe_emit_len, replace_bytes, replace_in, response_has_no_body, scan_close_hold, scan_with_tail,
};
pub(crate) use wire::{CredentialPair, Direction, Hit, LocalUpgrade, Location, PeerFact, Rewritten, UpgradeNote, Wire};
