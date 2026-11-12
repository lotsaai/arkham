//! Foreground daemon entrypoint and systemd user-service commands.

#[cfg(target_os = "linux")]
mod systemd;

use arkham_config::cli::{Cli, CliCommand};
use clap::{Args, Subcommand};

/// Arguments for daemon execution and user-service management.
#[derive(Args, Debug, Clone)]
#[command(arg_required_else_help = true)]
pub struct DaemonArgs {
  /// Select foreground execution or a service-management command.
  #[command(subcommand)]
  command: DaemonCommand,
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum DaemonCommand {
  /// Run the host daemon, optionally through the installed user service.
  Run {
    /// Start the installed systemd user service instead of running in the foreground.
    #[arg(long)]
    background: bool,
  },
  /// Print a systemd user unit using this executable's absolute path.
  Unit,
  /// Write the user unit and reload systemd without enabling or starting it.
  Install,
  /// Start the installed user service.
  Start,
  /// Stop the user service and its agent sessions.
  Stop,
  /// Restart the user service, terminating its current agent sessions.
  Restart,
  /// Show the service status; inactive services return systemctl's exit code.
  Status,
  /// Enable the installed service at user-manager startup.
  Enable,
  /// Disable automatic startup without stopping the running service.
  Disable,
  /// Follow service logs in the user journal.
  Logs,
}

impl CliCommand for DaemonArgs {
  type Error = eyre::Report;

  async fn run(self, _cli: &Cli, arkham_version: &str) -> Result<(), Self::Error> {
    #[cfg(target_os = "linux")]
    match self.command {
      DaemonCommand::Run { background: false } => crate::host::run(arkham_version).await,
      DaemonCommand::Run { background: true } | DaemonCommand::Start => systemd::UserService::systemctl("start").await,
      DaemonCommand::Unit => systemd::UserService::print_unit(),
      DaemonCommand::Install => systemd::UserService::install().await,
      DaemonCommand::Stop => systemd::UserService::systemctl("stop").await,
      DaemonCommand::Restart => systemd::UserService::systemctl("restart").await,
      DaemonCommand::Status => systemd::UserService::systemctl("status").await,
      DaemonCommand::Enable => systemd::UserService::systemctl("enable").await,
      DaemonCommand::Disable => systemd::UserService::systemctl("disable").await,
      DaemonCommand::Logs => systemd::UserService::logs().await,
    }
    #[cfg(not(target_os = "linux"))]
    {
      let _ = self.command;
      eyre::bail!("the host daemon runs on Linux, not this arkham {arkham_version} build")
    }
  }
}
