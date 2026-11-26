# shellcheck shell=bash
# Sourced first by every task that has to run in the arkham-dev machine.
# When ARKHAM_SANDBOX names the machine (mise.arch.toml sets it on the Arch
# workstation), it boots that machine, brings its target/ up to date, runs this
# same task there as eng, stops the machine and exits with the task's status.
# Inside the machine, and anywhere else, it is unset and the task runs where it is.
if [[ -n "${ARKHAM_SANDBOX:-}" ]]; then
  sandbox_checkout=/home/eng/github/lotsaai/arkham
  mise run sandbox:init
  if ! smolvm machine status --name "$ARKHAM_SANDBOX"; then
    mise run --force sandbox:init
  fi
  if [[ "$(smolvm machine status --name "$ARKHAM_SANDBOX" --json | jq -r .state)" != running ]]; then
    smolvm machine start --name "$ARKHAM_SANDBOX"
  fi
  trap 'smolvm machine stop --name "$ARKHAM_SANDBOX"' EXIT
  for _ in $(seq 1 120); do
    smolvm machine exec --name "$ARKHAM_SANDBOX" --user root -- \
      sh -c 'systemctl is-active --quiet docker && systemctl is-active --quiet containerd' && break
    sleep 1
  done
  smolvm machine exec --name "$ARKHAM_SANDBOX" --user root -- \
    sh -c 'systemctl is-active --quiet docker && systemctl is-active --quiet containerd'
  smolvm machine exec --stream --name "$ARKHAM_SANDBOX" --user root -- \
    su - eng -c "cd $sandbox_checkout && mise exec -- bash .mise/sandbox-build.sh"
  smolvm machine exec --stream --name "$ARKHAM_SANDBOX" --user root -- \
    su - eng -c "cd $sandbox_checkout"' && mise run --force "$@"' \
    zsh "${MISE_TASK_NAME:?run through mise}" "$@"
  exit
fi
