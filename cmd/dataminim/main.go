package main

import (
	"os"

	"github.com/dataminim/dataminim/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
