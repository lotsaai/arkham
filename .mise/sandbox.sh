# shellcheck shell=bash
# Sourced first by every task that has to run in the arkham-dev machine.
# When ARKHAM_SANDBOX names the warm checkpoint (mise.arch.toml sets it on the
# Arch workstation), it keeps the arkham-dev source machine running from that
# checkpoint, brings the source's target/ up to date, branches a throwaway
# machine from it, runs this same task there as eng, deletes the branch and
# exits with the task's status. Inside the machine, and anywhere else, it is
# unset and the task runs where it is. Only the source's build output survives
# the run; nothing the task writes outside the checkout does.
if [[ -n "${ARKHAM_SANDBOX:-}" ]]; then
  sandbox_checkout=/home/eng/github/lotsaai/arkham
  sandbox_source=arkham-dev
  mkdir -p "$MISE_CONFIG_ROOT/.cache/sandbox"
  # Concurrent tasks wait for one refresh and one source start; the rest find them ready.
  (
    flock 9
    mise run sandbox:init
    if ! smolvm machine status --name "$sandbox_source"; then
      smolvm machine create --name "$sandbox_source" --from "$ARKHAM_SANDBOX"
    fi
    if [[ "$(smolvm machine status --name "$sandbox_source" --json | jq -r .state)" != running ]]; then
      smolvm machine start --name "$sandbox_source"
    fi
  ) 9>"$MISE_CONFIG_ROOT/.cache/sandbox/init.lock"
  smolvm machine exec --stream --name "$sandbox_source" --user root -- \
    su - eng -c "cd $sandbox_checkout && mise exec -- bash .mise/sandbox-build.sh"
  sandbox_run="arkham-run-$$"
  trap 'smolvm machine delete --name "$sandbox_run" --force' EXIT
  smolvm machine branch --from "$sandbox_source" --name "$sandbox_run" --no-wait-ready
  smolvm machine exec --stream --name "$sandbox_run" --user root -- \
    su - eng -c "cd $sandbox_checkout"' && mise run --force "$@"' \
    zsh "${MISE_TASK_NAME:?run through mise}" "$@"
  exit
fi
