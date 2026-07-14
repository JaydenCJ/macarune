// Tests for the caveat grammar and its fail-closed evaluation semantics.
// Every operator is exercised on both the pass and the deny side, because a
// caveat that silently passes when it should deny is a privilege escalation.
package caveat

import (
	"strings"
	"testing"
	"time"
)

// ctx builds a typical tool-call context used across evaluation tests.
func ctx() Context {
	return Context{
		Tool:     "read_file",
		Args:     map[string]string{"path": "/workspace/notes.md", "bytes": "512"},
		Audience: "ci-runner",
		At:       time.Date(2026, 7, 13, 10, 0, 0, 0, time.UTC),
		AtSet:    true,
	}
}

// mustParse is a test helper that fails fast on grammar errors.
func mustParse(t *testing.T, raw string) Caveat {
	t.Helper()
	c, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(%q): %v", raw, err)
	}
	return c
}

func TestParseSplitsFieldOpValue(t *testing.T) {
	c := mustParse(t, "tool = read_file")
	if c.Field != "tool" || c.Op != OpEq || c.Value != "read_file" {
		t.Fatalf("got %+v", c)
	}
}

func TestParseKeepsSpacesInsideValue(t *testing.T) {
	// Argument values legitimately contain spaces (queries, messages).
	c := mustParse(t, "arg.query ^= weekly report for")
	if c.Value != "weekly report for" {
		t.Fatalf("value = %q", c.Value)
	}
}

func TestParseToleratesExtraWhitespaceAroundTokens(t *testing.T) {
	c := mustParse(t, "  tool   =   shell ")
	if c.String() != "tool = shell" {
		t.Fatalf("canonical form = %q", c.String())
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	malformed := []string{
		"", "   ", "\t", // blank
		"tool = a\ntool = b",                       // newlines could smuggle a second predicate past log review
		"tool", "tool =", "tool in", "arg.path ^=", // missing op or value
	}
	for _, raw := range malformed {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("Parse(%q) should fail", raw)
		}
	}
}

func TestParseAllowsExplicitEmptyValueForEquality(t *testing.T) {
	c := mustParse(t, `arg.flags = ""`)
	ok, _ := c.Eval(Context{Tool: "t", Args: map[string]string{"flags": ""}})
	if !ok {
		t.Fatal("empty-string equality should hold for an empty argument")
	}
}

func TestParseRejectsUnknownFieldOrOperator(t *testing.T) {
	rejected := []string{
		"user = alice", "scope in a,b", "args.path = /x", // unknown fields
		"tool == shell", "tool => x", "tool contains sh", // unknown operators
	}
	for _, raw := range rejected {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("Parse(%q) should fail", raw)
		}
	}
}

func TestParseEnforcesFieldOperatorMatrix(t *testing.T) {
	rejected := []string{
		"tool < shell", "aud >= ci", // ordered comparison on string fields
		"time = 2026-07-13T10:00:00Z",                               // exact-instant equality is never what a policy means
		"time < tomorrow", "time < 2026-07-13", "time < 1752300000", // non-RFC-3339 bounds
		"arg.path >= /workspace",                   // ordered comparison against a non-number
		"arg. = x", "arg.pa th = x", "arg.p$h = x", // bad arg names
		"tool in ,,", // empty in-set
	}
	for _, raw := range rejected {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("Parse(%q) should fail", raw)
		}
	}
}

func TestCanonicalStringNormalizesInSets(t *testing.T) {
	// Equivalent spellings must sign identically once canonicalized.
	a := mustParse(t, "tool in read_file, list_dir ,stat")
	b := mustParse(t, "tool in read_file,list_dir,stat")
	if a.String() != b.String() {
		t.Fatalf("canonical forms differ: %q vs %q", a.String(), b.String())
	}
}

func TestCanonicalStringRoundTrips(t *testing.T) {
	for _, raw := range []string{
		"tool = shell",
		"tool in a,b,c",
		"arg.path ^= /workspace/",
		"arg.bytes <= 4096",
		"time < 2026-08-01T00:00:00Z",
		`arg.flags = ""`,
	} {
		c := mustParse(t, raw)
		again := mustParse(t, c.String())
		if again.String() != c.String() {
			t.Fatalf("canonical form of %q is unstable: %q -> %q", raw, c.String(), again.String())
		}
	}
}

func TestEvalToolEquality(t *testing.T) {
	if ok, _ := mustParse(t, "tool = read_file").Eval(ctx()); !ok {
		t.Fatal("matching tool should pass")
	}
	ok, reason := mustParse(t, "tool = shell").Eval(ctx())
	if ok {
		t.Fatal("non-matching tool should deny")
	}
	if !strings.Contains(reason, "read_file") {
		t.Fatalf("reason should quote the actual tool, got %q", reason)
	}
}

func TestEvalNotEqual(t *testing.T) {
	if ok, _ := mustParse(t, "tool != shell").Eval(ctx()); !ok {
		t.Fatal("tool != shell should pass for read_file")
	}
	if ok, _ := mustParse(t, "tool != read_file").Eval(ctx()); ok {
		t.Fatal("tool != read_file should deny for read_file")
	}
}

func TestEvalInSet(t *testing.T) {
	if ok, _ := mustParse(t, "tool in read_file,list_dir").Eval(ctx()); !ok {
		t.Fatal("member should pass")
	}
	if ok, _ := mustParse(t, "tool in shell,exec").Eval(ctx()); ok {
		t.Fatal("non-member should deny")
	}
}

func TestEvalInSetRequiresExactMember(t *testing.T) {
	// "read" is a prefix of "read_file" but not a member.
	if ok, _ := mustParse(t, "tool in read,list_dir").Eval(ctx()); ok {
		t.Fatal("prefix of a member must not pass")
	}
}

func TestEvalGlob(t *testing.T) {
	cases := []struct {
		pattern string
		pass    bool
	}{
		{"tool ~ read_*", true},
		{"tool ~ *_file", true},
		{"tool ~ read?file", true},
		{"tool ~ *", true},
		{"tool ~ write_*", false},
		{"tool ~ read", false}, // no wildcard, not an exact match
	}
	for _, tc := range cases {
		if ok, _ := mustParse(t, tc.pattern).Eval(ctx()); ok != tc.pass {
			t.Fatalf("%q: got %v, want %v", tc.pattern, ok, tc.pass)
		}
	}
}

func TestGlobStarCrossesPathSeparators(t *testing.T) {
	// Unlike path.Match, '*' spans '/' — path scoping uses ^= instead.
	c := mustParse(t, "arg.path ~ /workspace/*.md")
	if ok, _ := c.Eval(ctx()); !ok {
		t.Fatal("glob should match /workspace/notes.md")
	}
	deep := ctx()
	deep.Args["path"] = "/workspace/a/b/notes.md"
	if ok, _ := c.Eval(deep); !ok {
		t.Fatal("'*' should cross '/' by design")
	}
}

func TestEvalPrefix(t *testing.T) {
	if ok, _ := mustParse(t, "arg.path ^= /workspace/").Eval(ctx()); !ok {
		t.Fatal("prefix should pass")
	}
	escaped := ctx()
	escaped.Args["path"] = "/etc/passwd"
	ok, reason := mustParse(t, "arg.path ^= /workspace/").Eval(escaped)
	if ok {
		t.Fatal("path outside the prefix must deny")
	}
	if !strings.Contains(reason, "/etc/passwd") {
		t.Fatalf("reason should quote the offending path, got %q", reason)
	}
}

func TestEvalNumericComparisons(t *testing.T) {
	cases := []struct {
		raw  string
		pass bool
	}{
		{"arg.bytes <= 512", true},
		{"arg.bytes < 512", false},
		{"arg.bytes >= 512", true},
		{"arg.bytes > 512", false},
		{"arg.bytes <= 4096", true},
		{"arg.bytes > 1024", false},
	}
	for _, tc := range cases {
		if ok, _ := mustParse(t, tc.raw).Eval(ctx()); ok != tc.pass {
			t.Fatalf("%q: got %v, want %v", tc.raw, ok, tc.pass)
		}
	}
}

func TestEvalNumericDeniesNonNumericArgument(t *testing.T) {
	c := ctx()
	c.Args["bytes"] = "lots"
	ok, reason := mustParse(t, "arg.bytes <= 4096").Eval(c)
	if ok {
		t.Fatal("non-numeric argument must fail closed")
	}
	if !strings.Contains(reason, "not a number") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestEvalMissingArgumentFailsClosed(t *testing.T) {
	ok, reason := mustParse(t, "arg.recipient = ops@example.test").Eval(ctx())
	if ok {
		t.Fatal("missing argument must deny, never default-allow")
	}
	if !strings.Contains(reason, "recipient") {
		t.Fatalf("reason should name the missing argument, got %q", reason)
	}
}

func TestEvalEmptyArgumentIsPresent(t *testing.T) {
	// An argument explicitly set to "" is present — distinct from missing.
	c := ctx()
	c.Args["mode"] = ""
	if ok, _ := mustParse(t, `arg.mode = ""`).Eval(c); !ok {
		t.Fatal("empty-but-present argument should satisfy equality with \"\"")
	}
}

func TestEvalAudience(t *testing.T) {
	if ok, _ := mustParse(t, "aud = ci-runner").Eval(ctx()); !ok {
		t.Fatal("matching audience should pass")
	}
	if ok, _ := mustParse(t, "aud = deploy-bot").Eval(ctx()); ok {
		t.Fatal("wrong audience should deny")
	}
}

func TestEvalTimeBounds(t *testing.T) {
	// ctx() is at 2026-07-13T10:00:00Z exactly.
	cases := []struct {
		raw  string
		pass bool
	}{
		{"time < 2026-07-13T10:00:01Z", true},
		{"time < 2026-07-13T10:00:00Z", false}, // strict: expiry instant denies
		{"time <= 2026-07-13T10:00:00Z", true},
		{"time > 2026-07-13T09:00:00Z", true},
		{"time >= 2026-07-13T10:00:00Z", true},
		{"time > 2026-07-13T10:00:00Z", false},
	}
	for _, tc := range cases {
		if ok, _ := mustParse(t, tc.raw).Eval(ctx()); ok != tc.pass {
			t.Fatalf("%q: got %v, want %v", tc.raw, ok, tc.pass)
		}
	}
}

func TestEvalTimeHonorsOffsets(t *testing.T) {
	// 10:00Z == 19:00+09:00; comparisons are instant-based, not textual.
	if ok, _ := mustParse(t, "time <= 2026-07-13T19:00:00+09:00").Eval(ctx()); !ok {
		t.Fatal("offset timestamps must compare as instants")
	}
}

func TestEvalTimeWithoutClockFailsClosed(t *testing.T) {
	c := ctx()
	c.AtSet = false
	ok, reason := mustParse(t, "time < 2099-01-01T00:00:00Z").Eval(c)
	if ok {
		t.Fatal("a verifier without a clock must deny time caveats")
	}
	if !strings.Contains(reason, "no evaluation time") {
		t.Fatalf("reason = %q", reason)
	}
}

func TestEvalDenialReasonsAreStable(t *testing.T) {
	// Reasons feed audit logs; pin the exact wording of the common ones.
	c := ctx()
	c.Tool = "shell"
	_, reason := mustParse(t, "tool in read_file,list_dir").Eval(c)
	want := `tool is "shell", not in {read_file, list_dir}`
	if reason != want {
		t.Fatalf("reason = %q, want %q", reason, want)
	}
}

func TestGlobMatchTable(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"", "", true},
		{"*", "", true},
		{"?", "", false},
		{"a*b", "ab", true},
		{"a*b", "axxxb", true},
		{"a*b", "axxxc", false},
		{"*.md", "notes.md", true},
		{"*.md", "notes.mdx", false},
		{"a**b", "ab", true},
		{"fs_*", "fs_read", true},
		{"fs_*", "net_fetch", false},
	}
	for _, tc := range cases {
		if got := globMatch(tc.pattern, tc.s); got != tc.want {
			t.Fatalf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}
