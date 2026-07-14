// Package token implements the macarune token itself: minting from a root
// key, offline attenuation by HMAC chaining, and the mrn1 wire encoding.
//
// The construction is the first-party core of macaroons (Birgisson et al.,
// 2014): the root signature is HMAC-SHA256 over a domain-separated preamble
// of the key id and token id, and every appended caveat re-keys the chain
//
//	sig_0 = HMAC(rootKey, "macarune/v1" || "\n" || kid || "\n" || id)
//	sig_n = HMAC(sig_{n-1}, caveat_n)
//
// so anyone holding a token can append caveats (narrowing it) without the
// root key, while removing or reordering caveats breaks the final tag.
// Only a verifier holding the root key can recompute and check the chain.
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/JaydenCJ/macarune/internal/caveat"
)

// Prefix marks the mrn1 wire encoding, so tokens are recognizable in logs
// and configs without decoding.
const Prefix = "mrn1."

// domain separates macarune signatures from any other HMAC use of the same
// key material. Bump alongside the wire version.
const domain = "macarune/v1"

// Hard limits enforced on decode, so a hostile token cannot make a verifier
// allocate without bound.
const (
	MaxCaveats   = 64
	MaxCaveatLen = 1024
	MinKeyLen    = 16
	sigLen       = sha256.Size
	maxWireLen   = 128 * 1024
	maxIdentLen  = 128
)

// Token is a decoded macarune token. Caveats are stored in canonical string
// form, in signing order.
type Token struct {
	Version int
	KID     string   // which root key signed this token
	ID      string   // per-token identifier (nonce); public, not secret
	Caveats []string // canonical caveat strings, oldest first
	Sig     []byte   // final HMAC-SHA256 tag over the whole chain
}

// wire is the JSON layout inside the base64url payload.
type wire struct {
	V   int      `json:"v"`
	KID string   `json:"kid"`
	ID  string   `json:"id"`
	Cav []string `json:"cav"`
	Sig string   `json:"sig"`
}

// Mint creates a new token under rootKey. Every caveat is parsed and
// canonicalized before signing, so a token that mints successfully always
// verifies against a well-formed chain.
func Mint(rootKey []byte, kid, id string, caveats []string) (*Token, error) {
	if len(rootKey) < MinKeyLen {
		return nil, fmt.Errorf("root key too short: %d bytes, need at least %d", len(rootKey), MinKeyLen)
	}
	if err := checkIdent("key id", kid); err != nil {
		return nil, err
	}
	if err := checkIdent("token id", id); err != nil {
		return nil, err
	}
	canon, err := canonicalize(caveats)
	if err != nil {
		return nil, err
	}
	return &Token{
		Version: 1,
		KID:     kid,
		ID:      id,
		Caveats: canon,
		Sig:     ComputeSig(rootKey, kid, id, canon),
	}, nil
}

// Attenuate returns a copy of t narrowed by the given caveats. No key is
// required: the existing tag keys the next HMAC link. The receiver is not
// mutated, so a broad token can be attenuated many different ways.
func Attenuate(t *Token, caveats ...string) (*Token, error) {
	if len(caveats) == 0 {
		return nil, fmt.Errorf("attenuate: no caveats given")
	}
	canon, err := canonicalize(caveats)
	if err != nil {
		return nil, err
	}
	if len(t.Caveats)+len(canon) > MaxCaveats {
		return nil, fmt.Errorf("attenuate: token would exceed %d caveats", MaxCaveats)
	}
	next := &Token{
		Version: t.Version,
		KID:     t.KID,
		ID:      t.ID,
		Caveats: append(append([]string(nil), t.Caveats...), canon...),
		Sig:     append([]byte(nil), t.Sig...),
	}
	for _, c := range canon {
		next.Sig = chain(next.Sig, c)
	}
	return next, nil
}

// ComputeSig recomputes the full HMAC chain from the root key. Verifiers
// compare its result against Token.Sig with hmac.Equal.
func ComputeSig(rootKey []byte, kid, id string, caveats []string) []byte {
	mac := hmac.New(sha256.New, rootKey)
	mac.Write([]byte(domain + "\n" + kid + "\n" + id))
	sig := mac.Sum(nil)
	for _, c := range caveats {
		sig = chain(sig, c)
	}
	return sig
}

// chain derives the next tag by using the previous tag as the HMAC key.
func chain(prev []byte, caveat string) []byte {
	mac := hmac.New(sha256.New, prev)
	mac.Write([]byte(caveat))
	return mac.Sum(nil)
}

// canonicalize parses and re-serializes each caveat so equivalent spellings
// sign identically.
func canonicalize(caveats []string) ([]string, error) {
	out := make([]string, 0, len(caveats))
	for _, raw := range caveats {
		c, err := caveat.Parse(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, c.String())
	}
	return out, nil
}

// checkIdent enforces the identifier alphabet shared by key ids and token
// ids. Whitespace is banned because both are joined with "\n" into the
// signed preamble; the length cap bounds decode allocations.
func checkIdent(what, s string) error {
	if s == "" {
		return fmt.Errorf("%s is empty", what)
	}
	if len(s) > maxIdentLen {
		return fmt.Errorf("%s longer than %d bytes", what, maxIdentLen)
	}
	if strings.IndexFunc(s, unicode.IsSpace) >= 0 {
		return fmt.Errorf("%s %q contains whitespace", what, s)
	}
	return nil
}

// Encode renders the token in mrn1 wire form: "mrn1." followed by the
// unpadded base64url of a compact JSON body.
func (t *Token) Encode() string {
	w := wire{
		V:   t.Version,
		KID: t.KID,
		ID:  t.ID,
		Cav: t.Caveats,
		Sig: base64.RawURLEncoding.EncodeToString(t.Sig),
	}
	body, err := json.Marshal(w)
	if err != nil {
		// Marshal of a struct of strings cannot fail; keep the API infallible.
		panic("token: marshal: " + err.Error())
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(body)
}

// Decode parses an mrn1 string back into a Token. Decode validates shape
// and size only — a decodable token is not a valid one. Caveat strings are
// deliberately NOT parsed here: a syntactically broken caveat must surface
// as a verification denial (fail-closed), not as a decode error, and
// inspect must still be able to display it.
func Decode(s string) (*Token, error) {
	s = strings.TrimSpace(s)
	if len(s) > maxWireLen {
		return nil, fmt.Errorf("token exceeds %d bytes", maxWireLen)
	}
	if !strings.HasPrefix(s, Prefix) {
		return nil, fmt.Errorf("not a macarune token: missing %q prefix", Prefix)
	}
	body, err := base64.RawURLEncoding.DecodeString(s[len(Prefix):])
	if err != nil {
		return nil, fmt.Errorf("bad token payload: %v", err)
	}
	var w wire
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return nil, fmt.Errorf("bad token body: %v", err)
	}
	if w.V != 1 {
		return nil, fmt.Errorf("unsupported token version %d", w.V)
	}
	if err := checkIdent("key id", w.KID); err != nil {
		return nil, err
	}
	if err := checkIdent("token id", w.ID); err != nil {
		return nil, err
	}
	if len(w.Cav) > MaxCaveats {
		return nil, fmt.Errorf("token carries %d caveats, limit is %d", len(w.Cav), MaxCaveats)
	}
	for i, c := range w.Cav {
		if len(c) > MaxCaveatLen {
			return nil, fmt.Errorf("caveat %d exceeds %d bytes", i, MaxCaveatLen)
		}
		if strings.ContainsAny(c, "\r\n") {
			return nil, fmt.Errorf("caveat %d spans multiple lines", i)
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(w.Sig)
	if err != nil {
		return nil, fmt.Errorf("bad signature encoding: %v", err)
	}
	if len(sig) != sigLen {
		return nil, fmt.Errorf("signature is %d bytes, want %d", len(sig), sigLen)
	}
	return &Token{Version: w.V, KID: w.KID, ID: w.ID, Caveats: w.Cav, Sig: sig}, nil
}
