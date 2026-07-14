// Package caveat implements macarune's first-party caveat language: small
// predicate strings of the form "<field> <op> <value>" that are appended to
// a token and evaluated against a verification-time request. Every caveat
// must hold for a request to be allowed, so appending caveats can only ever
// narrow authority — never widen it.
//
// Evaluation is strictly fail-closed: a missing argument, an absent
// evaluation time, a non-numeric value in a numeric comparison, or a caveat
// the verifier cannot parse all evaluate to "deny", each with a
// human-readable reason.
package caveat

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Op is a comparison operator in the caveat grammar.
type Op string

// The full operator set. Which operators are legal depends on the field:
// string fields (tool, aud, arg.*) take =, !=, in, ~ and ^=; ordered
// comparisons (<, <=, >, >=) are legal on time (RFC 3339) and on arg.*
// (decimal numbers).
const (
	OpEq     Op = "="  // exact string equality
	OpNeq    Op = "!=" // string inequality
	OpIn     Op = "in" // membership in a comma-separated set
	OpGlob   Op = "~"  // glob match: * = any run, ? = any single character
	OpPrefix Op = "^=" // string prefix match
	OpLt     Op = "<"
	OpLte    Op = "<="
	OpGt     Op = ">"
	OpGte    Op = ">="
)

// ArgPrefix marks fields that address a named request argument.
const ArgPrefix = "arg."

// Well-known non-argument fields.
const (
	FieldTool = "tool" // the tool the agent is invoking
	FieldAud  = "aud"  // the audience (which verifier/service this token is for)
	FieldTime = "time" // the verification-time clock, RFC 3339
)

// Caveat is one parsed predicate. Value holds the raw right-hand side; for
// OpIn it is a comma-separated set, for time comparisons an RFC 3339
// timestamp, for numeric comparisons a decimal number.
type Caveat struct {
	Field string
	Op    Op
	Value string
}

// Context carries the request-time facts a verifier evaluates caveats
// against. AtSet distinguishes "time not supplied" (fail-closed for time
// caveats) from the zero time.
type Context struct {
	Tool     string
	Args     map[string]string
	Audience string
	At       time.Time
	AtSet    bool
}

// Parse parses and validates a caveat string. The canonical serialization
// (String) is what gets signed into tokens, so Parse is deliberately strict:
// unknown fields, illegal field/operator pairings, malformed timestamps and
// non-numeric comparison values are all rejected at mint time rather than
// discovered at verify time.
func Parse(raw string) (Caveat, error) {
	if strings.ContainsAny(raw, "\r\n") {
		return Caveat{}, fmt.Errorf("caveat must be a single line")
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return Caveat{}, fmt.Errorf("empty caveat")
	}
	field, rest := splitToken(s)
	opText, value := splitToken(rest)
	if field == "" || opText == "" {
		return Caveat{}, fmt.Errorf("caveat %q: want \"<field> <op> <value>\"", raw)
	}
	op := Op(opText)
	if value == "" {
		// Comparing against the empty string is legal but must be written
		// explicitly as "" so a truncated caveat never parses.
		return Caveat{}, fmt.Errorf("caveat %q: missing value", raw)
	}
	if value == `""` {
		value = ""
	}
	c := Caveat{Field: field, Op: op, Value: value}
	if err := c.validate(); err != nil {
		return Caveat{}, fmt.Errorf("caveat %q: %v", raw, err)
	}
	return c, nil
}

// splitToken cuts s at the first run of spaces, returning the head token and
// the trimmed remainder. Values may contain internal spaces.
func splitToken(s string) (head, rest string) {
	i := strings.IndexFunc(s, unicode.IsSpace)
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeftFunc(s[i:], unicode.IsSpace)
}

// validate enforces the field/operator matrix and value well-formedness.
func (c Caveat) validate() error {
	ordered := c.Op == OpLt || c.Op == OpLte || c.Op == OpGt || c.Op == OpGte
	stringy := c.Op == OpEq || c.Op == OpNeq || c.Op == OpIn || c.Op == OpGlob || c.Op == OpPrefix
	if !ordered && !stringy {
		return fmt.Errorf("unknown operator %q", c.Op)
	}
	switch {
	case c.Field == FieldTime:
		if !ordered {
			return fmt.Errorf("field \"time\" only supports <, <=, >, >=")
		}
		if _, err := time.Parse(time.RFC3339, c.Value); err != nil {
			return fmt.Errorf("time value %q is not RFC 3339", c.Value)
		}
	case c.Field == FieldTool || c.Field == FieldAud:
		if ordered {
			return fmt.Errorf("field %q does not support ordered comparison", c.Field)
		}
	case strings.HasPrefix(c.Field, ArgPrefix):
		name := c.Field[len(ArgPrefix):]
		if !validArgName(name) {
			return fmt.Errorf("bad argument name %q", name)
		}
		if ordered {
			if _, err := strconv.ParseFloat(c.Value, 64); err != nil {
				return fmt.Errorf("value %q of an ordered comparison must be a decimal number", c.Value)
			}
		}
	default:
		return fmt.Errorf("unknown field %q (want tool, aud, time, or arg.<name>)", c.Field)
	}
	if c.Op == OpIn && len(splitSet(c.Value)) == 0 {
		return fmt.Errorf("\"in\" set is empty")
	}
	return nil
}

// validArgName restricts argument names to a safe identifier alphabet.
func validArgName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

// splitSet splits an "in" value into trimmed, non-empty members.
func splitSet(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// String renders the canonical single-space form that is signed into tokens.
// "in" sets are re-joined without spaces so that equivalent spellings
// canonicalize identically before signing.
func (c Caveat) String() string {
	v := c.Value
	if c.Op == OpIn {
		v = strings.Join(splitSet(v), ",")
	}
	if v == "" {
		v = `""`
	}
	return c.Field + " " + string(c.Op) + " " + v
}

// Eval evaluates the caveat against ctx. It returns ok=false with a concrete
// reason on any failure; reasons are stable strings suitable for CLI output
// and audit logs.
func (c Caveat) Eval(ctx Context) (ok bool, reason string) {
	if c.Field == FieldTime {
		return c.evalTime(ctx)
	}
	subject, ok := c.subject(ctx)
	if !ok {
		return false, fmt.Sprintf("argument %q not supplied", c.Field[len(ArgPrefix):])
	}
	switch c.Op {
	case OpEq:
		if subject == c.Value {
			return true, ""
		}
		return false, fmt.Sprintf("%s is %q, want %q", c.Field, subject, c.Value)
	case OpNeq:
		if subject != c.Value {
			return true, ""
		}
		return false, fmt.Sprintf("%s must not be %q", c.Field, c.Value)
	case OpIn:
		for _, member := range splitSet(c.Value) {
			if subject == member {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%s is %q, not in {%s}", c.Field, subject, strings.Join(splitSet(c.Value), ", "))
	case OpGlob:
		if globMatch(c.Value, subject) {
			return true, ""
		}
		return false, fmt.Sprintf("%s is %q, does not match %q", c.Field, subject, c.Value)
	case OpPrefix:
		if strings.HasPrefix(subject, c.Value) {
			return true, ""
		}
		return false, fmt.Sprintf("%s is %q, missing prefix %q", c.Field, subject, c.Value)
	case OpLt, OpLte, OpGt, OpGte:
		return c.evalNumeric(subject)
	}
	return false, fmt.Sprintf("unknown operator %q", c.Op)
}

// subject resolves the left-hand side of the caveat from the context. The
// second return is false only for a missing argument (fail-closed).
func (c Caveat) subject(ctx Context) (string, bool) {
	switch {
	case c.Field == FieldTool:
		return ctx.Tool, true
	case c.Field == FieldAud:
		return ctx.Audience, true
	case strings.HasPrefix(c.Field, ArgPrefix):
		v, present := ctx.Args[c.Field[len(ArgPrefix):]]
		return v, present
	}
	return "", true
}

// evalTime compares the verification clock against an RFC 3339 bound.
// A verifier that supplies no clock denies every time caveat.
func (c Caveat) evalTime(ctx Context) (bool, string) {
	if !ctx.AtSet {
		return false, "no evaluation time supplied for a time caveat"
	}
	bound, err := time.Parse(time.RFC3339, c.Value)
	if err != nil {
		return false, fmt.Sprintf("time bound %q is not RFC 3339", c.Value)
	}
	var pass bool
	switch c.Op {
	case OpLt:
		pass = ctx.At.Before(bound)
	case OpLte:
		pass = !ctx.At.After(bound)
	case OpGt:
		pass = ctx.At.After(bound)
	case OpGte:
		pass = !ctx.At.Before(bound)
	}
	if pass {
		return true, ""
	}
	return false, fmt.Sprintf("time %s is not %s %s",
		ctx.At.UTC().Format(time.RFC3339), c.Op, c.Value)
}

// evalNumeric compares an argument value numerically. Both sides must be
// decimal numbers; a non-numeric argument denies (fail-closed).
func (c Caveat) evalNumeric(subject string) (bool, string) {
	lhs, err := strconv.ParseFloat(subject, 64)
	if err != nil {
		return false, fmt.Sprintf("%s is %q, not a number", c.Field, subject)
	}
	rhs, err := strconv.ParseFloat(c.Value, 64)
	if err != nil {
		return false, fmt.Sprintf("bound %q is not a number", c.Value)
	}
	var pass bool
	switch c.Op {
	case OpLt:
		pass = lhs < rhs
	case OpLte:
		pass = lhs <= rhs
	case OpGt:
		pass = lhs > rhs
	case OpGte:
		pass = lhs >= rhs
	}
	if pass {
		return true, ""
	}
	return false, fmt.Sprintf("%s is %s, not %s %s", c.Field, subject, c.Op, c.Value)
}

// globMatch matches s against a pattern where '*' matches any run of
// characters (including '/') and '?' matches exactly one. Iterative
// backtracking, linear in len(pattern)+len(s) for a single '*' and
// worst-case quadratic overall — fine for the short strings caveats carry.
func globMatch(pattern, s string) bool {
	px, sx := 0, 0
	starPx, starSx := -1, 0
	for sx < len(s) {
		switch {
		case px < len(pattern) && (pattern[px] == '?' || pattern[px] == s[sx]):
			px++
			sx++
		case px < len(pattern) && pattern[px] == '*':
			starPx, starSx = px, sx
			px++
		case starPx >= 0:
			px = starPx + 1
			starSx++
			sx = starSx
		default:
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}
