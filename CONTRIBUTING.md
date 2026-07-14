# Contributing to macarune

Issues, discussions and pull requests are all welcome.

## Getting started

You need Go ≥1.22; nothing else — macarune is standard library only.

```bash
git clone https://github.com/JaydenCJ/macarune && cd macarune
go build ./...
go test ./...
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary and walks the full delegation story —
keygen, mint, keyless attenuation, allow, deny, tamper detection — asserting
on real CLI output and exit codes; it must finish by printing `SMOKE OK`.

## Before you open a pull request

1. `gofmt -l .` reports nothing (formatting is enforced).
2. `go vet ./...` passes with no findings.
3. `go test ./...` passes (89 deterministic tests, no network).
4. `bash scripts/smoke.sh` prints `SMOKE OK`.
5. Add tests for behavior changes; keep logic in pure, unit-testable
   modules (`caveat`, `token`, `verify` do no I/O — only `keyring` and the
   CLI touch the filesystem).

## Ground rules

- Keep dependencies at zero; adding one needs strong justification in the PR.
- No network calls, ever — minting, attenuation, and verification are pure
  computation plus local file reads. No telemetry.
- **Fail closed.** Any change to caveat evaluation must deny on missing
  facts, unparseable input, or ambiguity, and must come with a test proving
  the denial. A widening bug is a security bug.
- The wire format is versioned: `mrn1.` bodies never change shape. New
  fields or semantics mean `mrn2.`, negotiated in `docs/token-format.md`
  first.
- Signature comparisons go through `hmac.Equal` — never `==` or
  `bytes.Equal` — to stay constant-time.
- Code comments and doc comments are written in English.

## Reporting bugs

Include the output of `macarune version`, the exact command you ran, and —
for verification surprises — the output of `macarune inspect` on the token
plus the full `verify` command with its `--arg`/`--aud`/`--at` values, since
that is exactly what the verifier saw. Never post a production token or a
keyring file; re-create the shape with a throwaway key.

## Security

Please do not open public issues for security problems; use GitHub's
private vulnerability reporting on this repository instead.
