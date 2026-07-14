// Package verify is the trust boundary of macarune: it recomputes a token's
// HMAC chain from the root key and evaluates every caveat against the
// request. The design is deny-by-default — a request is allowed only when
// the signature checks AND all caveats hold; any parse failure, missing
// fact, or expired bound is a denial with a quotable reason.
package verify

import (
	"crypto/hmac"

	"github.com/JaydenCJ/macarune/internal/caveat"
	"github.com/JaydenCJ/macarune/internal/token"
)

// Request carries the facts about the tool call being authorized.
// It maps 1:1 onto caveat.Context.
type Request = caveat.Context

// Failure records one caveat that did not hold, with its position in the
// token and a human-readable reason.
type Failure struct {
	Index  int    `json:"index"`
	Caveat string `json:"caveat"`
	Reason string `json:"reason"`
}

// Result is a full verification verdict. When SigValid is false the caveats
// were never evaluated — an unauthentic token gets no further consideration.
type Result struct {
	OK       bool      `json:"ok"`
	SigValid bool      `json:"sig_valid"`
	Failures []Failure `json:"failures,omitempty"`
}

// Verify checks t against rootKey and req. The signature comparison is
// constant-time (hmac.Equal); caveat evaluation reports every failing
// caveat, not just the first, so callers can log a complete denial reason.
func Verify(rootKey []byte, t *token.Token, req Request) Result {
	want := token.ComputeSig(rootKey, t.KID, t.ID, t.Caveats)
	if !hmac.Equal(want, t.Sig) {
		return Result{
			OK:       false,
			SigValid: false,
			Failures: []Failure{{
				Index:  -1,
				Caveat: "",
				Reason: "signature mismatch: token was tampered with, truncated, or signed by a different key",
			}},
		}
	}
	res := Result{OK: true, SigValid: true}
	for i, raw := range t.Caveats {
		c, err := caveat.Parse(raw)
		if err != nil {
			// A caveat the verifier cannot understand must deny, never be
			// skipped: skipping would let an attacker widen a token by
			// appending garbage.
			res.OK = false
			res.Failures = append(res.Failures, Failure{Index: i, Caveat: raw, Reason: err.Error()})
			continue
		}
		if ok, reason := c.Eval(req); !ok {
			res.OK = false
			res.Failures = append(res.Failures, Failure{Index: i, Caveat: raw, Reason: reason})
		}
	}
	return res
}
