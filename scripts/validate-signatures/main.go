package main

import (
	"fmt"
	"io"
	"os"

	"github.com/cumakurt/garga/internal/vulnerability"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] == "" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(stderr, "usage: validate-signatures DIR")
		return 2
	}
	signatures, err := vulnerability.LoadDir(args[0])
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return 2
	}
	fmt.Fprintf(stdout, "validated %d signatures in %s\n", len(signatures), args[0])
	return 0
}
