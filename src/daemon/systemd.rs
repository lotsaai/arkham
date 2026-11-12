//! Systemd user-unit rendering, installation, and process control.

use std::path::Path;

use eyre::{WrapErr as _, eyre};
use tokio::process::Command;

const UNIT: &str = "arkham-daemon.service";

pub(super) struct UserService;

impl UserService {
  pub(super) fn print_unit() -> eyre::Result<()> {
    print!("{}", Self::unit(&std::env::current_exe()?)?);
    Ok(())
  }

  pub(super) async fn install() -> eyre::Result<()> {
    let directory = dirs::config_dir()
      .ok_or_else(|| eyre!("unable to resolve user config directory"))?
      .join("systemd/user");
    tokio::fs::create_dir_all(&directory)
      .await
      .wrap_err("creating systemd user directory")?;
    let path = directory.join(UNIT);
    tokio::fs::write(&path, Self::unit(&std::env::current_exe()?)?)
      .await
      .wrap_err("writing systemd user unit")?;
    Self::systemctl("daemon-reload").await?;
    println!("installed {}", path.display());
    Ok(())
  }

  pub(super) async fn logs() -> eyre::Result<()> {
    let status = Command::new("journalctl")
      .args(["--user", "--unit", UNIT, "--follow"])
      .status()
      .await
      .wrap_err("running journalctl")?;
    std::process::exit(status.code().unwrap_or(1));
  }

  pub(super) async fn systemctl(action: &str) -> eyre::Result<()> {
    let mut command = Command::new("systemctl");
    command.args(["--user", action]);
    if action != "daemon-reload" {
      command.arg(UNIT);
    }
    let status = command.status().await.wrap_err("running systemctl --user")?;
    if !status.success() {
      std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
  }

  fn unit(executable: &Path) -> eyre::Result<String> {
    let executable = executable.to_str().ok_or_else(|| eyre!("systemd executable path is not UTF-8"))?;
    let mut quoted = String::from("\"");
    for character in executable.chars() {
      match character {
        '\\' => quoted.push_str("\\\\"),
        '"' => quoted.push_str("\\\""),
        '%' => quoted.push_str("%%"),
        '$' => quoted.push_str("$$"),
        '\n' => quoted.push_str("\\n"),
        '\r' => quoted.push_str("\\r"),
        '\t' => quoted.push_str("\\t"),
        character if character.is_control() => return Err(eyre!("systemd executable path contains an unsupported control character")),
        character => quoted.push(character),
      }
    }
    quoted.push('"');
    Ok(format!(
      "[Unit]\nDescription=Arkham host daemon\n\n[Service]\nType=exec\nExecStart={quoted} daemon run\nWorkingDirectory=%h\nDelegate=yes\nRestart=on-failure\nRestartSec=5s\nUMask=0077\n\n[Install]\nWantedBy=default.target\n"
    ))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn executable_path_cannot_inject_unit_directives_or_expand_variables() {
    let unit = UserService::unit(Path::new("/opt/a b/%h/$HOME/\"arkham\\\n")).unwrap();
    assert!(unit.contains("ExecStart=\"/opt/a b/%%h/$$HOME/\\\"arkham\\\\\\n\" daemon run\n"));
    assert_eq!(unit.lines().filter(|line| line.starts_with("ExecStart=")).count(), 1);
    assert!(!unit.lines().any(|line| line.starts_with("Environment=")));
  }
}
