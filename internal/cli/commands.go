// Command implementations for the macarune CLI. Each run* function owns one
// subcommand: flag parsing, orchestration of the pure internal packages, and
// rendering. No business logic lives here.
package cli

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/JaydenCJ/macarune/internal/keyring"
	"github.com/JaydenCJ/macarune/internal/token"
	"github.com/JaydenCJ/macarune/internal/verify"
)

// newFlagSet builds a silent FlagSet whose errors we render ourselves.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// runKeygen generates a fresh root key inside a keyring file, creating the
// file when needed.
func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("keygen", stderr)
	path := fs.String("keyring", "", "keyring file to create or extend (required)")
	kid := fs.String("kid", "root", "id of the new key")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *path == "" {
		fmt.Fprintln(stderr, "macarune keygen: --keyring is required")
		return ExitUsage
	}
	kr, err := keyring.LoadOrNew(*path)
	if err != nil {
		fmt.Fprintf(stderr, "macarune keygen: %v\n", err)
		return ExitRuntime
	}
	if _, err := kr.Generate(*kid); err != nil {
		fmt.Fprintf(stderr, "macarune keygen: %v\n", err)
		return ExitRuntime
	}
	if err := kr.Save(*path); err != nil {
		fmt.Fprintf(stderr, "macarune keygen: %v\n", err)
		return ExitRuntime
	}
	total := len(kr.KIDs())
	noun := "keys"
	if total == 1 {
		noun = "key"
	}
	fmt.Fprintf(stdout, "generated key %q in %s (%d %s total)\n", *kid, *path, total, noun)
	return ExitOK
}

// runMint creates a token from a root key, with any number of initial
// caveats, and prints the encoded token.
func runMint(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("mint", stderr)
	path := fs.String("keyring", "", "keyring file holding the root key (required)")
	kid := fs.String("kid", "root", "id of the root key to mint under")
	id := fs.String("id", "", "token id (default: random 16-byte hex)")
	var caveats multiFlag
	fs.Var(&caveats, "caveat", "caveat to bake in at mint time (repeatable)")
	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}
	if *path == "" {
		fmt.Fprintln(stderr, "macarune mint: --keyring is required")
		return ExitUsage
	}
	kr, err := keyring.Load(*path)
	if err != nil {
		fmt.Fprintf(stderr, "macarune mint: %v\n", err)
		return ExitRuntime
	}
	key, err := kr.Key(*kid)
	if err != nil {
		fmt.Fprintf(stderr, "macarune mint: %v\n", err)
		return ExitRuntime
	}
	tokenID := *id
	if tokenID == "" {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			fmt.Fprintf(stderr, "macarune mint: %v\n", err)
			return ExitRuntime
		}
		tokenID = hex.EncodeToString(raw)
	}
	t, err := token.Mint(key, *kid, tokenID, caveats)
	if err != nil {
		fmt.Fprintf(stderr, "macarune mint: %v\n", err)
		return ExitUsage
	}
	fmt.Fprintln(stdout, t.Encode())
	return ExitOK
}

// runAttenuate narrows an existing token with more caveats. Deliberately
// keyless: this is the operation an agent performs before handing a token
// to a sub-agent.
func runAttenuate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("attenuate", stderr)
	var caveats multiFlag
	fs.Var(&caveats, "caveat", "caveat to append (repeatable, required)")
	positionals, err := parseInterleaved(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(caveats) == 0 {
		fmt.Fprintln(stderr, "macarune attenuate: at least one --caveat is required")
		return ExitUsage
	}
	t, _, code := readToken(positionals, stdin, stderr)
	if code != ExitOK {
		return code
	}
	narrowed, err := token.Attenuate(t, caveats...)
	if err != nil {
		fmt.Fprintf(stderr, "macarune attenuate: %v\n", err)
		return ExitUsage
	}
	fmt.Fprintln(stdout, narrowed.Encode())
	return ExitOK
}

// runInspect decodes a token and shows what it claims — without any key and
// therefore without any authenticity judgement, which the output says.
func runInspect(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("inspect", stderr)
	format := fs.String("format", "text", "output format: text or json")
	positionals, err := parseInterleaved(fs, args)
	if err != nil {
		return ExitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "macarune inspect: unknown --format %q (want text or json)\n", *format)
		return ExitUsage
	}
	t, _, code := readToken(positionals, stdin, stderr)
	if code != ExitOK {
		return code
	}
	if *format == "json" {
		out := struct {
			KID     string   `json:"kid"`
			ID      string   `json:"id"`
			Caveats []string `json:"caveats"`
			Sig     string   `json:"sig"`
		}{t.KID, t.ID, t.Caveats, base64.RawURLEncoding.EncodeToString(t.Sig)}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(stderr, "macarune inspect: %v\n", err)
			return ExitRuntime
		}
		return ExitOK
	}
	fmt.Fprintf(stdout, "macarune token (unverified — inspect never checks signatures)\n")
	fmt.Fprintf(stdout, "  kid      %s\n", t.KID)
	fmt.Fprintf(stdout, "  id       %s\n", t.ID)
	fmt.Fprintf(stdout, "  caveats  %d\n", len(t.Caveats))
	for i, c := range t.Caveats {
		fmt.Fprintf(stdout, "    [%d] %s\n", i, c)
	}
	fmt.Fprintf(stdout, "  sig      %s… (hmac-sha256, %d bytes)\n",
		hex.EncodeToString(t.Sig)[:16], len(t.Sig))
	return ExitOK
}

// runVerify checks a token against the root key and a described request,
// and turns the verdict into an exit code.
func runVerify(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet("verify", stderr)
	path := fs.String("keyring", "", "keyring file holding the root key (required)")
	tool := fs.String("tool", "", "tool the agent is invoking")
	aud := fs.String("aud", "", "audience presenting the token")
	at := fs.String("at", "now", "evaluation time, RFC 3339 or \"now\"")
	format := fs.String("format", "text", "output format: text or json")
	quiet := fs.Bool("quiet", false, "suppress output; verdict is the exit code")
	var argPairs multiFlag
	fs.Var(&argPairs, "arg", "request argument as key=value (repeatable)")
	positionals, err := parseInterleaved(fs, args)
	if err != nil {
		return ExitUsage
	}
	if *path == "" {
		fmt.Fprintln(stderr, "macarune verify: --keyring is required")
		return ExitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "macarune verify: unknown --format %q (want text or json)\n", *format)
		return ExitUsage
	}
	req := verify.Request{Tool: *tool, Audience: *aud, Args: map[string]string{}}
	for _, pair := range argPairs {
		k, v, ok := cutPair(pair)
		if !ok {
			fmt.Fprintf(stderr, "macarune verify: bad --arg %q, want key=value\n", pair)
			return ExitUsage
		}
		req.Args[k] = v
	}
	switch *at {
	case "now":
		req.At, req.AtSet = time.Now(), true
	case "":
		// No clock: every time caveat will fail closed.
	default:
		parsed, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			fmt.Fprintf(stderr, "macarune verify: --at %q is not RFC 3339\n", *at)
			return ExitUsage
		}
		req.At, req.AtSet = parsed, true
	}
	t, _, code := readToken(positionals, stdin, stderr)
	if code != ExitOK {
		return code
	}
	kr, err := keyring.Load(*path)
	if err != nil {
		fmt.Fprintf(stderr, "macarune verify: %v\n", err)
		return ExitRuntime
	}
	key, err := kr.Key(t.KID)
	if err != nil {
		fmt.Fprintf(stderr, "macarune verify: %v\n", err)
		return ExitRuntime
	}
	res := verify.Verify(key, t, req)
	if !*quiet {
		renderVerdict(stdout, t, res, *format)
	}
	if res.OK {
		return ExitOK
	}
	return ExitDeny
}

// renderVerdict prints the verification result in text or JSON.
func renderVerdict(w io.Writer, t *token.Token, res verify.Result, format string) {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Verdict string `json:"verdict"`
			KID     string `json:"kid"`
			ID      string `json:"id"`
			verify.Result
		}{verdictWord(res.OK), t.KID, t.ID, res})
		return
	}
	if res.OK {
		fmt.Fprintf(w, "allow  kid=%s id=%s  %d caveat(s) hold\n", t.KID, t.ID, len(t.Caveats))
		return
	}
	fmt.Fprintf(w, "deny  kid=%s id=%s  %d failure(s)\n", t.KID, t.ID, len(res.Failures))
	for _, f := range res.Failures {
		if f.Index < 0 {
			fmt.Fprintf(w, "  [sig] %s\n", f.Reason)
			continue
		}
		fmt.Fprintf(w, "  [%d] %s — %s\n", f.Index, f.Caveat, f.Reason)
	}
}

// verdictWord maps the boolean verdict onto the CLI vocabulary.
func verdictWord(ok bool) string {
	if ok {
		return "allow"
	}
	return "deny"
}

// cutPair splits "key=value" at the first '='.
func cutPair(s string) (k, v string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			if i == 0 {
				return "", "", false
			}
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
