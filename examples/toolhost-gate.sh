#!/usr/bin/env bash
# macarune as an exit-code policy gate: wrap tool execution in a function
# that consults `macarune verify --quiet` first. Nothing runs unless the
# token presented by the calling agent authorizes exactly that call.
set -euo pipefail

BIN="${MACARUNE:-macarune}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
KEYS="$WORKDIR/keys.json"
NOW="2026-07-13T10:00:00Z"

"$BIN" keygen --keyring "$KEYS" --kid root >/dev/null
TOKEN="$("$BIN" mint --keyring "$KEYS" --kid root --id agent-1 \
  --caveat "tool in echo,date" \
  --caveat "time < 2026-08-01T00:00:00Z")"

# run_tool TOKEN TOOL [ARGS...] — execute TOOL only if the token allows it.
run_tool() {
  local token="$1" tool="$2"
  shift 2
  if "$BIN" verify "$token" --keyring "$KEYS" --tool "$tool" \
    --at "$NOW" --quiet; then
    echo "[gate] allow: $tool $*"
    "$tool" "$@"
  else
    echo "[gate] deny:  $tool $*" >&2
    return 1
  fi
}

echo "== allowed tool passes through the gate"
run_tool "$TOKEN" echo "hello from a scoped agent"

echo
echo "== disallowed tool is stopped before it runs"
run_tool "$TOKEN" rm -rf "$WORKDIR/precious" || true

echo
echo "== gate demo complete"
