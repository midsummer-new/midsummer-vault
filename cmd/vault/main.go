package main

import (
	"os"

	"github.com/midsummer-new/midsummer-vault/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
