#!/usr/bin/env bash
# The macarune delegation story in one runnable script:
#
#   verifier (holds the root key)
#     └─ orchestrator agent (holds a broad token, NOT the key)
#          └─ research sub-agent (holds a narrowed token)
#
# The orchestrator narrows its own token for the sub-agent entirely offline —
# no keyring flag appears anywhere between mint and verify.
set -euo pipefail

BIN="${MACARUNE:-macarune}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
KEYS="$WORKDIR/keys.json"
NOW="2026-07-13T10:00:00Z"

echo "== verifier: generate a root key (stays on the tool host)"
"$BIN" keygen --keyring "$KEYS" --kid root

echo
echo "== verifier: mint a broad token for the orchestrator"
BROAD="$("$BIN" mint --keyring "$KEYS" --kid root --id orc-7 \
  --caveat "aud = toolhost")"
echo "$BROAD"

echo
echo "== orchestrator: narrow it for a read-only research sub-agent"
echo "   (offline — only the token itself is needed)"
NARROW="$(printf '%s\n' "$BROAD" | "$BIN" attenuate \
  --caveat "tool in read_file,list_dir" \
  --caveat "arg.path ^= /workspace/research/" \
  --caveat "time < 2026-07-13T12:00:00Z")"
echo "$NARROW"

echo
echo "== sub-agent presents its token; the tool host verifies each call"
echo
echo "-- read_file inside /workspace/research/ (should ALLOW):"
"$BIN" verify "$NARROW" --keyring "$KEYS" --aud toolhost --at "$NOW" \
  --tool read_file --arg path=/workspace/research/sources.md

echo
echo "-- shell (should DENY — outside the delegated tool set):"
"$BIN" verify "$NARROW" --keyring "$KEYS" --aud toolhost --at "$NOW" \
  --tool shell || true

echo
echo "-- read_file outside the sandbox (should DENY — path escape):"
"$BIN" verify "$NARROW" --keyring "$KEYS" --aud toolhost --at "$NOW" \
  --tool read_file --arg path=/etc/passwd || true

echo
echo "-- the orchestrator's own broad token still allows shell:"
"$BIN" verify "$BROAD" --keyring "$KEYS" --aud toolhost --at "$NOW" \
  --tool shell
