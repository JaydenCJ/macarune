// In-process integration tests for the CLI: every subcommand, both verdict
// exit codes, stdin piping, and the usage-error paths. No binary is built
// and nothing leaves the test's temp directory.
package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// run invokes the CLI in-process and captures everything.
func run(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code = Run(args, strings.NewReader(stdin), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// setup creates a keyring and mints a delegated token, returning the keyring
// path and the encoded token — the fixture most CLI tests start from.
func setup(t *testing.T) (keyringPath, tok string) {
	t.Helper()
	keyringPath = filepath.Join(t.TempDir(), "keys.json")
	code, _, stderr := run(t, "", "keygen", "--keyring", keyringPath, "--kid", "root")
	if code != ExitOK {
		t.Fatalf("keygen: exit %d, stderr %q", code, stderr)
	}
	code, out, stderr := run(t, "",
		"mint", "--keyring", keyringPath, "--kid", "root", "--id", "tok-1",
		"--caveat", "tool in read_file,list_dir",
		"--caveat", "arg.path ^= /workspace/",
	)
	if code != ExitOK {
		t.Fatalf("mint: exit %d, stderr %q", code, stderr)
	}
	return keyringPath, strings.TrimSpace(out)
}

func TestVersionPrintsSemver(t *testing.T) {
	code, out, _ := run(t, "", "--version")
	if code != ExitOK || out != "macarune 0.1.0\n" {
		t.Fatalf("exit %d, out %q", code, out)
	}
}

func TestNoArgsPrintsUsageAndExits2(t *testing.T) {
	code, _, stderr := run(t, "")
	if code != ExitUsage || !strings.Contains(stderr, "Usage:") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestUnknownCommandExits2(t *testing.T) {
	code, _, stderr := run(t, "", "frobnicate")
	if code != ExitUsage || !strings.Contains(stderr, "frobnicate") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestKeygenRefusesDuplicateKid(t *testing.T) {
	path, _ := setup(t)
	code, _, stderr := run(t, "", "keygen", "--keyring", path, "--kid", "root")
	if code != ExitRuntime || !strings.Contains(stderr, "already exists") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestMintEmitsDecodableToken(t *testing.T) {
	_, tok := setup(t)
	if !strings.HasPrefix(tok, "mrn1.") {
		t.Fatalf("token %q lacks the mrn1. prefix", tok)
	}
	code, out, _ := run(t, "", "inspect", tok)
	if code != ExitOK || !strings.Contains(out, "tool in read_file,list_dir") {
		t.Fatalf("inspect: exit %d, out %q", code, out)
	}
}

func TestMintRandomIDsDiffer(t *testing.T) {
	path, _ := setup(t)
	_, a, _ := run(t, "", "mint", "--keyring", path, "--kid", "root")
	_, b, _ := run(t, "", "mint", "--keyring", path, "--kid", "root")
	if a == b {
		t.Fatal("two mints without --id must get distinct random ids")
	}
}

func TestMintRejectsBadCaveatWithExit2(t *testing.T) {
	path, _ := setup(t)
	code, _, stderr := run(t, "",
		"mint", "--keyring", path, "--kid", "root", "--caveat", "no such grammar")
	if code != ExitUsage || !strings.Contains(stderr, "caveat") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestMintMissingKeyExitsRuntime(t *testing.T) {
	path, _ := setup(t)
	code, _, stderr := run(t, "", "mint", "--keyring", path, "--kid", "ghost")
	if code != ExitRuntime || !strings.Contains(stderr, `"ghost"`) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestVerifyAllowsInScopeRequest(t *testing.T) {
	path, tok := setup(t)
	code, out, _ := run(t, "",
		"verify", tok, "--keyring", path,
		"--tool", "read_file", "--arg", "path=/workspace/notes.md")
	if code != ExitOK || !strings.HasPrefix(out, "allow") {
		t.Fatalf("exit %d, out %q", code, out)
	}
}

func TestVerifyDeniesOutOfScopeToolWithReason(t *testing.T) {
	path, tok := setup(t)
	code, out, _ := run(t, "",
		"verify", tok, "--keyring", path,
		"--tool", "shell", "--arg", "path=/workspace/notes.md")
	if code != ExitDeny {
		t.Fatalf("exit %d, want %d", code, ExitDeny)
	}
	if !strings.Contains(out, "deny") || !strings.Contains(out, `"shell"`) {
		t.Fatalf("denial should quote the offending tool: %q", out)
	}
}

func TestVerifyQuietSpeaksOnlyInExitCodes(t *testing.T) {
	path, tok := setup(t)
	code, out, _ := run(t, "",
		"verify", tok, "--keyring", path, "--tool", "shell", "--quiet")
	if code != ExitDeny || out != "" {
		t.Fatalf("exit %d, out %q", code, out)
	}
}

func TestVerifyJSONVerdict(t *testing.T) {
	path, tok := setup(t)
	code, out, _ := run(t, "",
		"verify", tok, "--keyring", path, "--tool", "shell", "--format", "json")
	if code != ExitDeny {
		t.Fatalf("exit %d", code)
	}
	var v struct {
		Verdict  string `json:"verdict"`
		SigValid bool   `json:"sig_valid"`
		Failures []struct {
			Caveat string `json:"caveat"`
			Reason string `json:"reason"`
		} `json:"failures"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("verdict is not JSON: %v\n%s", err, out)
	}
	if v.Verdict != "deny" || !v.SigValid || len(v.Failures) == 0 {
		t.Fatalf("unexpected verdict: %+v", v)
	}
}

func TestAttenuatePipesThroughStdin(t *testing.T) {
	path, tok := setup(t)
	code, narrowed, stderr := run(t, tok+"\n",
		"attenuate", "--caveat", "time < 2026-01-01T00:00:00Z")
	if code != ExitOK {
		t.Fatalf("attenuate: exit %d, stderr %q", code, stderr)
	}
	// The narrowed token is expired at any --at in 2026-07; verify denies.
	code, out, _ := run(t, "",
		"verify", strings.TrimSpace(narrowed), "--keyring", path,
		"--tool", "read_file", "--arg", "path=/workspace/a",
		"--at", "2026-07-13T00:00:00Z")
	if code != ExitDeny || !strings.Contains(out, "time") {
		t.Fatalf("exit %d, out %q", code, out)
	}
}

func TestAttenuateCannotWidenScope(t *testing.T) {
	// The attack the whole tool exists to stop: a sub-agent appending a
	// permissive caveat gains nothing, because verification is a conjunction.
	path, tok := setup(t)
	_, widened, _ := run(t, "", "attenuate", tok, "--caveat", "tool ~ *")
	code, _, _ := run(t, "",
		"verify", strings.TrimSpace(widened), "--keyring", path, "--tool", "shell")
	if code != ExitDeny {
		t.Fatal("appending a broad caveat must not authorize a denied tool")
	}
}

func TestAttenuateRequiresACaveat(t *testing.T) {
	_, tok := setup(t)
	code, _, stderr := run(t, "", "attenuate", tok)
	if code != ExitUsage || !strings.Contains(stderr, "--caveat") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestTamperedTokenIsDeniedAtSigLevel(t *testing.T) {
	path, tok := setup(t)
	// Flip one character inside the payload (keeping base64url-legal chars).
	body := []byte(tok)
	i := len(tok) - 10
	if body[i] == 'A' {
		body[i] = 'B'
	} else {
		body[i] = 'A'
	}
	code, out, stderr := run(t, "",
		"verify", string(body), "--keyring", path, "--tool", "read_file",
		"--arg", "path=/workspace/x")
	// Depending on which byte flips, the token fails decode (usage) or the
	// signature check (deny) — both refuse; what it must never do is allow.
	if code == ExitOK {
		t.Fatalf("tampered token was allowed: out %q stderr %q", out, stderr)
	}
}

func TestInspectJSONListsCaveats(t *testing.T) {
	_, tok := setup(t)
	code, out, _ := run(t, "", "inspect", tok, "--format", "json")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	var v struct {
		KID     string   `json:"kid"`
		ID      string   `json:"id"`
		Caveats []string `json:"caveats"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("inspect output is not JSON: %v", err)
	}
	if v.KID != "root" || v.ID != "tok-1" || len(v.Caveats) != 2 {
		t.Fatalf("unexpected inspect payload: %+v", v)
	}
}

func TestInspectReadsStdinAndWarnsUnverified(t *testing.T) {
	_, tok := setup(t)
	code, out, _ := run(t, tok, "inspect")
	if code != ExitOK || !strings.Contains(out, "unverified") {
		t.Fatalf("exit %d, out %q", code, out)
	}
}

func TestInspectRejectsGarbageWithExit2(t *testing.T) {
	code, _, stderr := run(t, "", "inspect", "not-a-token")
	if code != ExitUsage || !strings.Contains(stderr, "mrn1.") {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestVerifyUsageErrorsExit2(t *testing.T) {
	path, tok := setup(t)
	code, _, stderr := run(t, "",
		"verify", tok, "--keyring", path, "--tool", "read_file", "--arg", "novalue")
	if code != ExitUsage || !strings.Contains(stderr, "key=value") {
		t.Fatalf("bad --arg: exit %d, stderr %q", code, stderr)
	}
	code, _, stderr = run(t, "",
		"verify", tok, "--keyring", path, "--tool", "read_file", "--at", "yesterday")
	if code != ExitUsage || !strings.Contains(stderr, "RFC 3339") {
		t.Fatalf("bad --at: exit %d, stderr %q", code, stderr)
	}
}

func TestVerifyUnknownKidExitsRuntime(t *testing.T) {
	// Token minted under a keyring the verifier does not have.
	otherPath, tok := setup(t)
	_ = otherPath
	emptyPath := filepath.Join(t.TempDir(), "other.json")
	run(t, "", "keygen", "--keyring", emptyPath, "--kid", "different")
	code, _, stderr := run(t, "",
		"verify", tok, "--keyring", emptyPath, "--tool", "read_file")
	if code != ExitRuntime || !strings.Contains(stderr, `"root"`) {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
}

func TestVerifyEmptyAtFailsTimeCaveatsClosed(t *testing.T) {
	path, tok := setup(t)
	_, narrowed, _ := run(t, "",
		"attenuate", tok, "--caveat", "time < 2099-01-01T00:00:00Z")
	code, out, _ := run(t, "",
		"verify", strings.TrimSpace(narrowed), "--keyring", path,
		"--tool", "read_file", "--arg", "path=/workspace/a", "--at", "")
	if code != ExitDeny || !strings.Contains(out, "no evaluation time") {
		t.Fatalf("exit %d, out %q", code, out)
	}
}

func TestHelpMentionsEverySubcommand(t *testing.T) {
	code, out, _ := run(t, "", "help")
	if code != ExitOK {
		t.Fatalf("exit %d", code)
	}
	for _, sub := range []string{"keygen", "mint", "attenuate", "inspect", "verify"} {
		if !strings.Contains(out, sub) {
			t.Fatalf("help is missing %q", sub)
		}
	}
}
