// Command sanitize-csv pseudonymizes Vault client-activity export CSVs so they
// can be shared. It is the Go port of scripts/sanitize_csv.py; see
// cmd/sanitize-csv/README.md and scripts/README.md.
package main

import (
	"os"

	"github.com/vault-csv-normalizer/internal/sanitizer"
)

func main() {
	os.Exit(sanitizer.Main(os.Args[1:], os.Stderr))
}
