# The mrn1 token format and caveat grammar

This document specifies macarune's wire format and verification semantics
precisely enough to write an independent verifier. Everything here is
enforced by the test suite.

## Construction

macarune tokens are the first-party core of macaroons (Birgisson et al.,
*Macaroons: Cookies with Contextual Caveats*, NDSS 2014), built on
HMAC-SHA256 only:

```
sig_0 = HMAC(rootKey, "macarune/v1" + "\n" + kid + "\n" + id)
sig_n = HMAC(sig_{n-1}, caveat_n)      # the previous tag is the next key
tag   = sig_N                          # shipped with the token
```

Consequences:

- **Anyone holding a token can append caveats** — computing the next HMAC
  link needs only the current tag. This is attenuation, and it is keyless
  and offline by construction.
- **Nobody can remove, edit, or reorder caveats** without the root key: any
  such change requires recomputing an interior `sig_i`, and every interior
  tag is destroyed by the chaining (only the final tag ships).
- **Appending can only narrow.** Verification is a conjunction over all
  caveats, so an extra caveat can never authorize a request the shorter
  chain denied.
- The `kid` and `id` are joined with `"\n"` and identifiers reject
  whitespace, so `(kid="a", id="b-c")` can never collide with
  `(kid="a-b", id="c")`.

## Wire encoding

A token is the string `mrn1.` followed by the **unpadded base64url** of a
JSON body with exactly these fields (unknown fields are rejected):

```json
{
  "v":   1,
  "kid": "root",
  "id":  "orc-7",
  "cav": ["aud = toolhost", "tool in read_file,list_dir"],
  "sig": "<base64url of the 32-byte final tag>"
}
```

Decode limits (all rejections, not truncations): whole token ≤ 128 KiB,
≤ 64 caveats, each caveat ≤ 1024 bytes and single-line, `sig` exactly
32 bytes, identifiers ≤ 128 bytes with no whitespace.

## Caveat grammar

One predicate per caveat: `<field> <op> <value>`. The value is everything
after the operator (it may contain spaces). Minting canonicalizes
whitespace and `in`-set spacing before signing, so equivalent spellings
produce identical signatures.

| Field | Meaning | Operators |
|---|---|---|
| `tool` | tool name of the request | `=` `!=` `in` `~` `^=` |
| `aud` | audience (which verifier the token is for) | `=` `!=` `in` `~` `^=` |
| `arg.<name>` | one named request argument | `=` `!=` `in` `~` `^=` `<` `<=` `>` `>=` |
| `time` | verification clock, RFC 3339 | `<` `<=` `>` `>=` |

| Operator | Semantics |
|---|---|
| `=` / `!=` | exact string (in)equality; the empty string is written `""` |
| `in` | membership in a comma-separated set, exact match per member |
| `~` | glob: `*` matches any run (including `/`), `?` one character |
| `^=` | string prefix — the operator for path scoping |
| `<` `<=` `>` `>=` | on `time`: instant comparison; on `arg.*`: decimal numeric |

## Fail-closed rules

A request is allowed **only** when the signature chain recomputes exactly
(compared in constant time) **and** every caveat holds. Each of the
following denies, with a quotable reason:

1. An argument named by a caveat that the request did not supply.
2. A `time` caveat when the verifier provides no evaluation clock.
3. A non-numeric argument in a numeric comparison.
4. A caveat the verifier cannot parse — a hostile holder *can* extend the
   HMAC chain with garbage (attenuation is keyless by design), so garbage
   must deny rather than be skipped.

A token with **zero caveats is a bearer credential** for everything its
root key guards. Mint with at least an `aud` caveat in anything real.

## What macarune deliberately does not do

- **No third-party caveats** (discharge macaroons) in v0.1.0 — the caveat
  language is first-party only. On the roadmap.
- **No revocation state.** Verification is pure computation; keep lifetimes
  short with `time <` instead of maintaining a deny-list. Rotating the root
  key revokes everything minted under it.
- **No stateful limits** (call budgets, rate caps) — those need a counter
  somewhere, which is exactly the server dependency macarune avoids.
- **Possession is authority.** Anyone holding a token can use everything it
  permits; treat tokens like passwords in transit and at rest.
