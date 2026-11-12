//! Export host-prepared mounts for the container-backed protocol fixture.

use std::collections::BTreeMap;
use std::path::PathBuf;

use arkham_config::WriteProfile;
use arkham_session::{CaPaths, prepare_session};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut args = std::env::args_os().skip(1);
  let root = PathBuf::from(args.next().ok_or("missing workspace")?);
  let scratch = PathBuf::from(args.next().ok_or("missing scratch directory")?);
  let cert = PathBuf::from(args.next().ok_or("missing CA certificate")?);
  std::fs::create_dir_all(&scratch)?;
  let session = prepare_session(
    &root,
    &scratch,
    WriteProfile::WorkspaceWrite,
    CaPaths {
      cert: &cert,
      source: &cert,
    },
    env!("CARGO_PKG_VERSION"),
    &BTreeMap::new(),
  )
  .await?;
  std::fs::write(scratch.join("plan.json"), serde_json::to_vec(&session.plan)?)?;
  Ok(())
}
