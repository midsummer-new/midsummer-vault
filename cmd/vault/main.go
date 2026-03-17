package main

import (
	"os"

	"github.com/Reichel1/midsummer/vault-cli/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
