// Tests for minting, offline attenuation, the HMAC chain, and the mrn1 wire
// encoding. The tampering cases matter most: every way of editing a token
// without the root key must break the final tag.
package token

import (
	"bytes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// testKey is a fixed 32-byte key so every signature in this file is
// reproducible run to run.
var testKey = []byte("0123456789abcdef0123456789abcdef")

// mintBroad mints the token most tests start from.
func mintBroad(t *testing.T) *Token {
	t.Helper()
	tok, err := Mint(testKey, "root", "tok-1", []string{"tool in read_file,list_dir"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return tok
}

func TestMintProducesVerifiableChain(t *testing.T) {
	tok := mintBroad(t)
	want := ComputeSig(testKey, "root", "tok-1", tok.Caveats)
	if !hmac.Equal(want, tok.Sig) {
		t.Fatal("freshly minted token must verify against its own chain")
	}
}

func TestMintIsDeterministic(t *testing.T) {
	a := mintBroad(t)
	b := mintBroad(t)
	if a.Encode() != b.Encode() {
		t.Fatal("same key, id, and caveats must encode identically")
	}
}

func TestMintCanonicalizesCaveats(t *testing.T) {
	tok, err := Mint(testKey, "root", "tok-1", []string{"  tool   in  read_file , list_dir "})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if tok.Caveats[0] != "tool in read_file,list_dir" {
		t.Fatalf("caveat not canonicalized: %q", tok.Caveats[0])
	}
	if tok.Encode() != mintBroad(t).Encode() {
		t.Fatal("equivalent caveat spellings must sign identically")
	}
}

func TestMintRejectsBadInputs(t *testing.T) {
	if _, err := Mint([]byte("too-short"), "root", "tok-1", nil); err == nil {
		t.Fatal("a short root key should be rejected")
	}
	if _, err := Mint(testKey, "root", "tok-1", []string{"tool != "}); err == nil {
		t.Fatal("unparseable caveat should be rejected at mint time")
	}
	badIdents := []struct{ kid, id string }{
		{"", "tok-1"},
		{"root", ""},
		{"my key", "tok-1"},                // whitespace would collide with the "\n" preamble joins
		{"root", "tok\n1"},                 // embedded newline
		{"root", strings.Repeat("x", 129)}, // over the length cap
	}
	for _, tc := range badIdents {
		if _, err := Mint(testKey, tc.kid, tc.id, nil); err == nil {
			t.Fatalf("Mint(kid=%q, id=%q) should fail", tc.kid, tc.id)
		}
	}
}

func TestMintWithNoCaveatsIsBearerRoot(t *testing.T) {
	tok, err := Mint(testKey, "root", "tok-1", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(tok.Caveats) != 0 {
		t.Fatalf("caveats = %v", tok.Caveats)
	}
	want := ComputeSig(testKey, "root", "tok-1", nil)
	if !hmac.Equal(want, tok.Sig) {
		t.Fatal("caveat-free chain mismatch")
	}
}

func TestAttenuateNeedsNoKeyAndVerifies(t *testing.T) {
	// The core property: attenuation uses only the token itself.
	tok := mintBroad(t)
	narrowed, err := Attenuate(tok, "arg.path ^= /workspace/")
	if err != nil {
		t.Fatalf("Attenuate: %v", err)
	}
	want := ComputeSig(testKey, "root", "tok-1", narrowed.Caveats)
	if !hmac.Equal(want, narrowed.Sig) {
		t.Fatal("attenuated token must verify against the root key it never saw")
	}
}

func TestAttenuateEqualsMintingWithAllCaveats(t *testing.T) {
	tok := mintBroad(t)
	narrowed, err := Attenuate(tok, "arg.path ^= /workspace/", "time < 2026-08-01T00:00:00Z")
	if err != nil {
		t.Fatalf("Attenuate: %v", err)
	}
	direct, err := Mint(testKey, "root", "tok-1", []string{
		"tool in read_file,list_dir",
		"arg.path ^= /workspace/",
		"time < 2026-08-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if narrowed.Encode() != direct.Encode() {
		t.Fatal("chained attenuation must equal minting with the full caveat list")
	}
}

func TestAttenuateDoesNotMutateOriginal(t *testing.T) {
	tok := mintBroad(t)
	before := tok.Encode()
	if _, err := Attenuate(tok, "aud = ci"); err != nil {
		t.Fatalf("Attenuate: %v", err)
	}
	if tok.Encode() != before {
		t.Fatal("Attenuate must return a copy, not mutate the receiver")
	}
}

func TestAttenuateRejectsEmptyAndInvalid(t *testing.T) {
	tok := mintBroad(t)
	if _, err := Attenuate(tok); err == nil {
		t.Fatal("attenuating with zero caveats should fail")
	}
	if _, err := Attenuate(tok, "nonsense"); err == nil {
		t.Fatal("unparseable caveat should be rejected")
	}
}

func TestAttenuateEnforcesCaveatCap(t *testing.T) {
	tok := mintBroad(t)
	var err error
	for i := 0; i < MaxCaveats; i++ {
		tok, err = Attenuate(tok, "aud = ci")
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Fatal("caveat cap should eventually reject further attenuation")
	}
}

func TestEncodeRoundTrips(t *testing.T) {
	tok := mintBroad(t)
	back, err := Decode(tok.Encode())
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if back.KID != tok.KID || back.ID != tok.ID || !bytes.Equal(back.Sig, tok.Sig) {
		t.Fatalf("round trip changed the token: %+v", back)
	}
	if len(back.Caveats) != 1 || back.Caveats[0] != tok.Caveats[0] {
		t.Fatalf("caveats = %v", back.Caveats)
	}
}

func TestEncodeIsPrefixedAndURLSafe(t *testing.T) {
	enc := mintBroad(t).Encode()
	if !strings.HasPrefix(enc, "mrn1.") {
		t.Fatalf("missing prefix: %q", enc)
	}
	if strings.ContainsAny(enc[len("mrn1."):], "+/=\n ") {
		t.Fatalf("payload must be unpadded base64url: %q", enc)
	}
}

func TestDecodeAcceptsSurroundingWhitespace(t *testing.T) {
	// Tokens get pasted from terminals; trailing newlines must not matter.
	if _, err := Decode("  " + mintBroad(t).Encode() + "\n"); err != nil {
		t.Fatalf("Decode with whitespace: %v", err)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	for _, s := range []string{
		"",
		"not-a-token",
		"mrn1.",
		"mrn1.!!!!",
		"mrn2." + base64.RawURLEncoding.EncodeToString([]byte(`{"v":1}`)),
	} {
		if _, err := Decode(s); err == nil {
			t.Fatalf("Decode(%q) should fail", s)
		}
	}
}

// reencode is a test helper that re-wraps a mutated wire body.
func reencode(t *testing.T, w wire) string {
	t.Helper()
	body, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(body)
}

// decodeWire is a test helper that exposes the raw wire struct of a token.
func decodeWire(t *testing.T, enc string) wire {
	t.Helper()
	body, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(enc, Prefix))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var w wire
	if err := json.Unmarshal(body, &w); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return w
}

func TestDecodeRejectsWrongVersionUnknownFieldsAndBadSig(t *testing.T) {
	w := decodeWire(t, mintBroad(t).Encode())

	v2 := w
	v2.V = 2
	if _, err := Decode(reencode(t, v2)); err == nil {
		t.Fatal("version 2 should be rejected")
	}

	shortSig := w
	shortSig.Sig = base64.RawURLEncoding.EncodeToString([]byte("short"))
	if _, err := Decode(reencode(t, shortSig)); err == nil {
		t.Fatal("truncated signature should be rejected")
	}

	body, _ := json.Marshal(map[string]any{"v": 1, "kid": "root", "id": "x",
		"cav": []string{}, "sig": w.Sig, "extra": true})
	if _, err := Decode(Prefix + base64.RawURLEncoding.EncodeToString(body)); err == nil {
		t.Fatal("unknown wire fields should be rejected")
	}
}

func TestDecodeRejectsOversizedCaveatLists(t *testing.T) {
	w := decodeWire(t, mintBroad(t).Encode())
	w.Cav = make([]string, MaxCaveats+1)
	for i := range w.Cav {
		w.Cav[i] = "aud = ci"
	}
	if _, err := Decode(reencode(t, w)); err == nil {
		t.Fatal("caveat-count bomb should be rejected at decode")
	}
	w = decodeWire(t, mintBroad(t).Encode())
	w.Cav = []string{"arg.q = " + strings.Repeat("x", MaxCaveatLen)}
	if _, err := Decode(reencode(t, w)); err == nil {
		t.Fatal("oversized caveat should be rejected at decode")
	}
}

func TestTamperingBreaksTheChain(t *testing.T) {
	tok := mintBroad(t)
	narrowed, err := Attenuate(tok, "arg.path ^= /workspace/")
	if err != nil {
		t.Fatalf("Attenuate: %v", err)
	}
	mutations := map[string]func(w *wire){
		"edit a caveat":       func(w *wire) { w.Cav[0] = "tool in read_file,list_dir,shell" },
		"drop a caveat":       func(w *wire) { w.Cav = w.Cav[:1] },
		"reorder caveats":     func(w *wire) { w.Cav[0], w.Cav[1] = w.Cav[1], w.Cav[0] },
		"swap the token id":   func(w *wire) { w.ID = "tok-2" },
		"swap the key id":     func(w *wire) { w.KID = "other" },
		"append without hmac": func(w *wire) { w.Cav = append(w.Cav, "aud = ci") },
	}
	for name, mutate := range mutations {
		w := decodeWire(t, narrowed.Encode())
		mutate(&w)
		forged, err := Decode(reencode(t, w))
		if err != nil {
			// Some mutations may fail decode outright; that is also a defense.
			continue
		}
		want := ComputeSig(testKey, forged.KID, forged.ID, forged.Caveats)
		if hmac.Equal(want, forged.Sig) {
			t.Fatalf("%s: forged token still verifies", name)
		}
	}
}

func TestDifferentKeysProduceDifferentSigs(t *testing.T) {
	otherKey := []byte("ffffffffffffffffffffffffffffffff")
	a, _ := Mint(testKey, "root", "tok-1", nil)
	b, _ := Mint(otherKey, "root", "tok-1", nil)
	if hmac.Equal(a.Sig, b.Sig) {
		t.Fatal("distinct keys must yield distinct signatures")
	}
}

func TestDomainSeparationOfKidAndID(t *testing.T) {
	// kid="a", id="b/c" must not collide with kid="a/b", id="c" — the "\n"
	// joins plus the whitespace ban on identifiers prevent recombination.
	a := ComputeSig(testKey, "a", "b-c", nil)
	b := ComputeSig(testKey, "a-b", "c", nil)
	if hmac.Equal(a, b) {
		t.Fatal("preamble fields must be domain-separated")
	}
}
