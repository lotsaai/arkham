//! Command-line surface: global flags, the subcommand trait, and the backend
//! switch shared by generation and serving.
//!
//! The globals live beside the config overlay because [`load`](crate::config::load)
//! takes them as its highest-precedence layer. Each subcommand's args struct
//! lives with its implementation — workspace commands in `arkham-compose`, the
//! rest in the binary — and implements [`CliCommand`].

use std::path::PathBuf;

use clap::{Args, ValueEnum};

/// Global flags, flattened into the binary's parser.
#[derive(Args, Debug, Clone)]
pub struct Cli {
  /// Config file replacing the project layer.
  #[arg(long, global = true, help = "config file replacing the project layer")]
  pub config: Option<PathBuf>,
}

/// One subcommand: its args struct plus how it runs. The binary dispatches
/// each parsed subcommand through this one async method, so adding a command
/// is a new args struct plus one impl — never another match arm with inline
/// logic. The program boots on the tokio runtime, so every implementation is
/// async and awaits its real work; none of them block.
pub trait CliCommand {
  /// This command's failure; the binary renders it.
  type Error;
  /// Run the command against the parsed globals.
  ///
  /// `arkham_version` is the binary's own version for anything naming the
  /// arkham image; commands that need nothing versioned ignore it.
  ///
  /// # Errors
  ///
  /// Returns whatever the command's own fallibility is: a missing workspace,
  /// an unreadable file, a failed child process.
  fn run(self, cli: &Cli, arkham_version: &str) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Proxy capture mode.
#[derive(ValueEnum, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProxyBackend {
  /// Explicit listener only; no transparent capture.
  #[default]
  None,
  /// Kernel: cgroup socket hooks rewrite destinations to loopback
  /// listeners; captures TCP and connected UDP (relay only). Needs
  /// `CAP_BPF` + `CAP_NET_ADMIN`, and a cgroup holding the workload with
  /// arkham itself outside it.
  Ebpf,
}
