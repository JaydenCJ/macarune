// Package cli implements the macarune command-line interface. Run takes
// argv plus explicit stdin/stdout/stderr, and returns an exit code, so the
// whole surface is testable in-process without building a binary.
package cli

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/JaydenCJ/macarune/internal/token"
	"github.com/JaydenCJ/macarune/internal/version"
)

// Exit codes, documented in the README. `verify` uses ExitDeny as its
// machine-readable verdict.
const (
	ExitOK      = 0
	ExitDeny    = 1
	ExitUsage   = 2
	ExitRuntime = 3
)

// maxStdinToken bounds how much of stdin a token read will consume.
const maxStdinToken = 256 * 1024

// Run dispatches argv and returns the process exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return ExitUsage
	}
	switch args[0] {
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "mint":
		return runMint(args[1:], stdout, stderr)
	case "attenuate":
		return runAttenuate(args[1:], stdin, stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdin, stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdin, stdout, stderr)
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "macarune %s\n", version.Version)
		return ExitOK
	case "help", "--help", "-h":
		usage(stdout)
		return ExitOK
	default:
		fmt.Fprintf(stderr, "macarune: unknown command %q\n\n", args[0])
		usage(stderr)
		return ExitUsage
	}
}

// usage prints the top-level help.
func usage(w io.Writer) {
	fmt.Fprint(w, `macarune — mint and verify attenuated capability tokens, offline

Usage:
  macarune keygen    --keyring FILE [--kid ID]
  macarune mint      --keyring FILE [--kid ID] [--id TOKEN_ID] [--caveat C]...
  macarune attenuate [TOKEN] --caveat C [--caveat C]...
  macarune inspect   [TOKEN] [--format text|json]
  macarune verify    [TOKEN] --keyring FILE [--tool NAME] [--arg K=V]...
                     [--aud NAME] [--at RFC3339|now] [--format text|json] [--quiet]
  macarune version

TOKEN may be passed as an argument or piped on stdin. Caveats look like
"tool in read_file,list_dir", "arg.path ^= /workspace/",
"time < 2026-08-01T00:00:00Z" — see docs/token-format.md for the grammar.

Exit codes: 0 ok/allow, 1 deny, 2 usage error, 3 runtime error.
`)
}

// parseInterleaved parses fs over args while collecting positional
// arguments that appear before, between, or after flags — the standard
// library's FlagSet stops at the first non-flag, which would force users to
// put the token last. A bare "-" (stdin marker) is kept as a positional.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positionals, nil
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
}

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// readToken resolves the token from the positional argument (or "-") or,
// when absent, from stdin — so tokens pipe naturally between subcommands.
func readToken(positional []string, stdin io.Reader, stderr io.Writer) (*token.Token, string, int) {
	var raw string
	switch {
	case len(positional) > 1:
		fmt.Fprintln(stderr, "macarune: expected at most one TOKEN argument")
		return nil, "", ExitUsage
	case len(positional) == 1 && positional[0] != "-":
		raw = positional[0]
	default:
		data, err := io.ReadAll(io.LimitReader(stdin, maxStdinToken))
		if err != nil {
			fmt.Fprintf(stderr, "macarune: reading token from stdin: %v\n", err)
			return nil, "", ExitRuntime
		}
		raw = strings.TrimSpace(string(data))
		if raw == "" {
			fmt.Fprintln(stderr, "macarune: no token: pass one as an argument or pipe it on stdin")
			return nil, "", ExitUsage
		}
	}
	t, err := token.Decode(raw)
	if err != nil {
		fmt.Fprintf(stderr, "macarune: %v\n", err)
		return nil, "", ExitUsage
	}
	return t, raw, ExitOK
}
