// Command macarune mints and verifies attenuated capability tokens for
// scoping agent tool access — offline, with pure HMAC, no token server.
package main

import (
	"os"

	"github.com/JaydenCJ/macarune/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
