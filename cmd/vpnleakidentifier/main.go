// File: cmd/vpnleakidentifier/main.go (complete file)

package main

import (
	"os"

	"github.com/baptistax/vpnleakidentifier/internal/cli"
)

func main() {
	code := cli.Run(os.Args[1:])
	os.Exit(code)
}
