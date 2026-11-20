//! Cgroup delegation through the user's systemd manager.

use futures::StreamExt as _;
use zbus::{Connection, Error as BusError, OwnedObjectPath, Proxy, Variant};

use crate::Error;

async fn manager() -> Result<Proxy<'static>, Error> {
  let connection = Connection::session().await.map_err(bus)?;
  Proxy::new(
    &connection,
    "org.freedesktop.systemd1",
    "/org/freedesktop/systemd1",
    "org.freedesktop.systemd1.Manager",
  )
  .await
  .map_err(bus)
}

/// Move this process into a new transient scope with `Delegate=yes`.
pub(crate) async fn delegate_self() -> Result<(), Error> {
  let manager = manager().await?;
  let mut removed = manager.receive_signal("JobRemoved").await.map_err(bus)?;
  let () = manager.call("Subscribe", &()).await.map_err(bus)?;
  let pid = std::process::id();
  let unit = format!("arkham-daemon-{pid}.scope");
  let properties: Vec<(&str, Variant<'_>)> = vec![("PIDs", Variant::from(vec![pid])), ("Delegate", Variant::from(true))];
  let auxiliary: Vec<(&str, Vec<(&str, Variant<'_>)>)> = Vec::new();
  let job: OwnedObjectPath = manager
    .call("StartTransientUnit", &(unit.as_str(), "fail", properties, auxiliary))
    .await
    .map_err(bus)?;
  while let Some(message) = removed.next().await {
    let (_, path, _, result): (u32, OwnedObjectPath, String, String) = message.body().deserialize().map_err(bus)?;
    if path == job {
      return if result == "done" {
        Ok(())
      } else {
        Err(Error::SystemdJob { unit, result })
      };
    }
  }
  Err(Error::SystemdJobLost { unit })
}

/// Move this process into `subcgroup` of the delegated `unit`.
pub(crate) async fn attach_self(unit: &str, subcgroup: &str) -> Result<(), Error> {
  let manager = manager().await?;
  manager
    .call("AttachProcessesToUnit", &(unit, subcgroup, vec![std::process::id()]))
    .await
    .map_err(bus)
}

fn bus(source: BusError) -> Error {
  Error::SystemdBus { source }
}
