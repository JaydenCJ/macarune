// Tests for the verifier: the end-to-end trust decision. These cases model
// the delegation story macarune exists for — an orchestrator narrows a token
// for a sub-agent, and the verifier must honor exactly that narrowing.
package verify

import (
	"strings"
	"testing"
	"time"

	"github.com/JaydenCJ/macarune/internal/token"
)

var rootKey = []byte("0123456789abcdef0123456789abcdef")

// delegated mints the canonical scenario: a broad orchestrator token,
// attenuated for a read-only sub-agent confined to /workspace.
func delegated(t *testing.T) *token.Token {
	t.Helper()
	broad, err := token.Mint(rootKey, "root", "orc-7", []string{"aud = toolhost"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	narrow, err := token.Attenuate(broad,
		"tool in read_file,list_dir",
		"arg.path ^= /workspace/",
		"time < 2026-07-13T12:00:00Z",
	)
	if err != nil {
		t.Fatalf("Attenuate: %v", err)
	}
	return narrow
}

// okRequest is a request the delegated token should allow.
func okRequest() Request {
	return Request{
		Tool:     "read_file",
		Args:     map[string]string{"path": "/workspace/notes.md"},
		Audience: "toolhost",
		At:       time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC),
		AtSet:    true,
	}
}

func TestAllowWhenAllCaveatsHold(t *testing.T) {
	res := Verify(rootKey, delegated(t), okRequest())
	if !res.OK || !res.SigValid || len(res.Failures) != 0 {
		t.Fatalf("expected clean allow, got %+v", res)
	}
}

func TestDenyToolOutsideTheSet(t *testing.T) {
	req := okRequest()
	req.Tool = "shell"
	res := Verify(rootKey, delegated(t), req)
	if res.OK {
		t.Fatal("shell is not in the delegated tool set")
	}
	if !res.SigValid {
		t.Fatal("signature is fine; only the caveat should fail")
	}
}

func TestDenyPathEscape(t *testing.T) {
	req := okRequest()
	req.Args["path"] = "/etc/passwd"
	res := Verify(rootKey, delegated(t), req)
	if res.OK {
		t.Fatal("path outside /workspace/ must deny")
	}
	if got := res.Failures[0].Caveat; !strings.Contains(got, "arg.path") {
		t.Fatalf("failure should point at the path caveat, got %q", got)
	}
}

func TestDenyAfterExpiry(t *testing.T) {
	req := okRequest()
	req.At = time.Date(2026, 7, 13, 12, 0, 1, 0, time.UTC)
	if Verify(rootKey, delegated(t), req).OK {
		t.Fatal("expired token must deny")
	}
}

func TestDenyWrongAudience(t *testing.T) {
	req := okRequest()
	req.Audience = "another-service"
	if Verify(rootKey, delegated(t), req).OK {
		t.Fatal("audience mismatch must deny")
	}
}

func TestDenyCollectsEveryFailure(t *testing.T) {
	// Audit logs want the complete denial reason, not just the first hit.
	req := Request{Tool: "shell", Args: map[string]string{"path": "/etc/x"},
		Audience: "nobody", At: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), AtSet: true}
	res := Verify(rootKey, delegated(t), req)
	if len(res.Failures) != 4 {
		t.Fatalf("expected all 4 caveats to fail, got %d: %+v", len(res.Failures), res.Failures)
	}
	for i, f := range res.Failures {
		if f.Reason == "" || f.Caveat == "" {
			t.Fatalf("failure %d lacks caveat/reason: %+v", i, f)
		}
	}
}

func TestDenyWrongKeyWithoutEvaluatingCaveats(t *testing.T) {
	otherKey := []byte("ffffffffffffffffffffffffffffffff")
	res := Verify(otherKey, delegated(t), okRequest())
	if res.OK || res.SigValid {
		t.Fatal("wrong key must invalidate the signature")
	}
	if len(res.Failures) != 1 || res.Failures[0].Index != -1 {
		t.Fatalf("expected the single sig failure, got %+v", res.Failures)
	}
}

func TestDenyForgedCaveatWidening(t *testing.T) {
	// An attacker rewrites the tool set to include shell but cannot fix the
	// tag without the root key.
	tok := delegated(t)
	forged := *tok
	forged.Caveats = append([]string(nil), tok.Caveats...)
	forged.Caveats[1] = "tool in read_file,list_dir,shell"
	req := okRequest()
	req.Tool = "shell"
	res := Verify(rootKey, &forged, req)
	if res.OK || res.SigValid {
		t.Fatal("widened caveat list must fail the signature check")
	}
}

func TestDenyUnparseableCaveatFailsClosed(t *testing.T) {
	// A hostile holder CAN extend the HMAC chain with garbage (attenuation
	// is keyless by design) — so garbage must deny, never be skipped.
	tok := delegated(t)
	garbage := "totally not a caveat"
	forged := *tok
	forged.Caveats = append(append([]string(nil), tok.Caveats...), garbage)
	forged.Sig = token.ComputeSig(rootKey, tok.KID, tok.ID, forged.Caveats)
	res := Verify(rootKey, &forged, okRequest())
	if res.OK {
		t.Fatal("unparseable caveat must deny even with a valid chain")
	}
	if !res.SigValid {
		t.Fatal("the chain itself is valid here; the caveat is what fails")
	}
	last := res.Failures[len(res.Failures)-1]
	if last.Caveat != garbage {
		t.Fatalf("failure should quote the garbage caveat, got %+v", last)
	}
}

func TestAttenuationNeverWidens(t *testing.T) {
	// Property check across a range of extra caveats: any request denied by
	// the parent token stays denied by every attenuation of it.
	parent := delegated(t)
	deniedReq := okRequest()
	deniedReq.Tool = "shell" // denied by the parent
	extras := []string{"tool = shell", "tool ~ *", "aud = toolhost", "arg.path ^= /"}
	for _, extra := range extras {
		child, err := token.Attenuate(parent, extra)
		if err != nil {
			t.Fatalf("Attenuate(%q): %v", extra, err)
		}
		if Verify(rootKey, child, deniedReq).OK {
			t.Fatalf("attenuating with %q widened the token", extra)
		}
	}
}

func TestCaveatFreeTokenAllowsEverything(t *testing.T) {
	// Documented behavior: a bare root token is a bearer credential.
	bare, err := token.Mint(rootKey, "root", "bare-1", nil)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	req := Request{Tool: "anything", Args: map[string]string{}}
	if !Verify(rootKey, bare, req).OK {
		t.Fatal("caveat-free token should allow any request")
	}
}

func TestVerifyAfterWireRoundTrip(t *testing.T) {
	// The full pipeline: mint -> attenuate -> encode -> decode -> verify.
	enc := delegated(t).Encode()
	back, err := token.Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !Verify(rootKey, back, okRequest()).OK {
		t.Fatal("token must survive the wire round trip")
	}
}
