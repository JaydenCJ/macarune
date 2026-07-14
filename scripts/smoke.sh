#!/usr/bin/env bash
# End-to-end smoke test for macarune: builds the binary, then walks the full
# delegation story — keygen, mint, keyless attenuation, inspect, verify allow
# and deny, tamper detection — asserting on real CLI output and exit codes.
# No network, idempotent, finishes in seconds.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/macarune"
KEYS="$WORKDIR/keys.json"
NOW="2026-07-13T10:00:00Z"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/macarune) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" --version | grep -qx "macarune 0.1.0" || fail "--version mismatch"

echo "3. keygen creates an owner-only keyring"
"$BIN" keygen --keyring "$KEYS" --kid root >/dev/null || fail "keygen failed"
[ -f "$KEYS" ] || fail "keyring file missing"
if [ "$(uname -s)" != "Windows_NT" ]; then
  PERM="$(stat -c '%a' "$KEYS" 2>/dev/null || stat -f '%Lp' "$KEYS")"
  [ "$PERM" = "600" ] || fail "keyring mode is $PERM, want 600"
fi

echo "4. mint a broad orchestrator token"
BROAD="$("$BIN" mint --keyring "$KEYS" --kid root --id orc-7 \
  --caveat "aud = toolhost")"
case "$BROAD" in mrn1.*) ;; *) fail "token lacks mrn1. prefix" ;; esac

echo "5. attenuate offline (no keyring flag anywhere) via stdin pipe"
NARROW="$(printf '%s\n' "$BROAD" | "$BIN" attenuate \
  --caveat "tool in read_file,list_dir" \
  --caveat "arg.path ^= /workspace/" \
  --caveat "time < 2026-07-13T12:00:00Z")"
[ "$NARROW" != "$BROAD" ] || fail "attenuation returned the same token"

echo "6. inspect lists every caveat without a key"
INSPECT="$("$BIN" inspect "$NARROW")"
echo "$INSPECT" | grep -q "unverified" || fail "inspect should warn unverified"
echo "$INSPECT" | grep -q "tool in read_file,list_dir" || fail "caveat missing"
echo "$INSPECT" | grep -q "caveats  4" || fail "caveat count wrong"

echo "7. verify allows the in-scope request"
"$BIN" verify "$NARROW" --keyring "$KEYS" --tool read_file \
  --arg path=/workspace/notes.md --aud toolhost --at "$NOW" \
  | grep -q "^allow" || fail "in-scope request should be allowed"

echo "8. verify denies an out-of-scope tool with exit 1 and a reason"
set +e
OUT="$("$BIN" verify "$NARROW" --keyring "$KEYS" --tool shell \
  --arg path=/workspace/notes.md --aud toolhost --at "$NOW")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "deny should exit 1, got $CODE"
echo "$OUT" | grep -q 'tool is "shell"' || fail "denial reason missing"

echo "9. the parent token still allows what the child cannot"
"$BIN" verify "$BROAD" --keyring "$KEYS" --tool shell \
  --aud toolhost --at "$NOW" --quiet || fail "broad token should allow shell"

echo "10. expiry denies after the time bound"
set +e
"$BIN" verify "$NARROW" --keyring "$KEYS" --tool read_file \
  --arg path=/workspace/notes.md --aud toolhost \
  --at "2026-07-13T12:00:01Z" --quiet
[ $? -eq 1 ] || fail "expired token should exit 1"
set -e

echo "11. a sub-agent appending 'tool ~ *' gains nothing"
WIDENED="$(printf '%s\n' "$NARROW" | "$BIN" attenuate --caveat "tool ~ *")"
set +e
"$BIN" verify "$WIDENED" --keyring "$KEYS" --tool shell \
  --arg path=/workspace/notes.md --aud toolhost --at "$NOW" --quiet
[ $? -eq 1 ] || fail "appended caveat must not widen scope"
set -e

echo "12. tampering with the payload is refused"
TAMPERED="$(printf '%s' "$NARROW" | sed 's/./A/60')"
set +e
"$BIN" verify "$TAMPERED" --keyring "$KEYS" --tool read_file \
  --arg path=/workspace/notes.md --aud toolhost --at "$NOW" --quiet 2>/dev/null
[ $? -ne 0 ] || fail "tampered token must never verify"
set -e

echo "13. JSON verdicts are machine-readable"
"$BIN" verify "$NARROW" --keyring "$KEYS" --tool read_file \
  --arg path=/workspace/notes.md --aud toolhost --at "$NOW" --format json \
  | grep -q '"verdict": "allow"' || fail "json verdict missing"

echo "14. usage errors exit 2"
set +e
"$BIN" verify "$NARROW" --keyring "$KEYS" --tool read_file --at yesterday \
  >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --at should exit 2"
"$BIN" inspect not-a-token >/dev/null 2>&1
[ $? -eq 2 ] || fail "garbage token should exit 2"
set -e

echo "SMOKE OK"
