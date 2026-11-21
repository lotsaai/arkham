# shellcheck shell=bash
# Sourced first by every task that has to run in the arkham-dev machine.
# When ARKHAM_SANDBOX names the warm checkpoint (mise.arch.toml sets it on the
# Arch workstation), it restores that checkpoint into a throwaway machine, runs
# this same task there as eng, deletes the machine and exits with the task's
# status. Inside the machine, and anywhere else, it is unset and the task runs
# where it is. Nothing the task writes outside the checkout survives the run.
if [[ -n "${ARKHAM_SANDBOX:-}" ]]; then
  mkdir -p "$MISE_CONFIG_ROOT/.cache/sandbox"
  # Concurrent tasks wait for one refresh; the rest find it fresh.
  flock "$MISE_CONFIG_ROOT/.cache/sandbox/init.lock" mise run sandbox:init
  sandbox_run="arkham-run-$$"
  smolvm machine create --name "$sandbox_run" --from "$ARKHAM_SANDBOX"
  trap 'smolvm machine delete --name "$sandbox_run" --force' EXIT
  smolvm machine start --name "$sandbox_run"
  smolvm machine exec --stream --name "$sandbox_run" --user root -- \
    su - eng -c 'cd /home/eng/github/lotsaai/arkham && mise run --force "$@"' \
    zsh "${MISE_TASK_NAME:?run through mise}" "$@"
  exit
fi
