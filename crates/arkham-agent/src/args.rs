//! Launch a confined host agent.

use std::ffi::OsString;
use std::path::PathBuf;

use arkham_config::WriteProfile;
use arkham_config::cli::{Cli, CliCommand};
use clap::Args;

use crate::Error;

/// Arguments for the `agent` command.
#[derive(Args, Debug, Clone)]
pub struct AgentArgs {
  /// Workspace directory; defaults to the current directory.
  pub workspace: Option<PathBuf>,
  /// Command to run instead of the configured shell, after `--`.
  #[arg(last = true)]
  pub command: Vec<OsString>,
  /// Filesystem write profile for the host backend.
  #[arg(long, value_enum, default_value_t = WriteProfile::WorkspaceWrite)]
  pub write_profile: WriteProfile,
}

impl CliCommand for AgentArgs {
  type Error = Error;

  #[cfg(target_os = "linux")]
  async fn run(self, _cli: &Cli, _arkham_version: &str) -> Result<(), Self::Error> {
    crate::linux::agent(self.write_profile, self.workspace.as_deref(), &self.command).await
  }

  #[cfg(not(target_os = "linux"))]
  fn run(self, _cli: &Cli, _arkham_version: &str) -> impl Future<Output = Result<(), Self::Error>> + Send {
    std::future::ready(Err(Error::HostLinuxOnly))
  }
}
