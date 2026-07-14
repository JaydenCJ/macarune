# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-13

### Added

- Macaroon-style capability tokens built on HMAC-SHA256 chaining: the root
  tag signs a domain-separated `kid`/`id` preamble and every appended caveat
  re-keys the chain, so holders attenuate offline while removal, edits, and
  reordering break the final tag.
- First-party caveat language (`<field> <op> <value>`) over `tool`, `aud`,
  `arg.<name>`, and `time`: equality, set membership, glob (`*`/`?`),
  prefix (`^=`) for path scoping, numeric comparisons for arguments, and
  RFC 3339 instant comparisons for expiry windows — canonicalized before
  signing so equivalent spellings sign identically.
- Strictly fail-closed verification: constant-time tag comparison, denial
  on missing arguments, absent clocks, non-numeric comparisons, and
  unparseable caveats, with every failing caveat reported alongside a
  stable, quotable reason.
- `mrn1.` wire encoding — unpadded base64url of a strict JSON body — with
  decode-time size caps (64 caveats, 1 KiB each, 128 KiB total) and
  unknown-field rejection.
- CLI: `keygen`, `mint`, `attenuate` (keyless, pipes via stdin), `inspect`
  (explicitly unverified), and `verify` with `--tool`/`--arg`/`--aud`/`--at`,
  text and JSON verdicts, `--quiet`, and exit codes 0 allow / 1 deny /
  2 usage / 3 runtime.
- JSON keyring with 0600 permissions, atomic writes, multiple named root
  keys, and refusal to silently overwrite a key id.
- Runnable examples (`examples/delegate.sh`, `examples/toolhost-gate.sh`)
  and a wire-format/grammar specification (`docs/token-format.md`).
- 89 deterministic offline tests (unit + in-process CLI integration,
  including forgery and widening attacks) and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/macarune/releases/tag/v0.1.0
