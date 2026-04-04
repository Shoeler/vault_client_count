package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/vault-csv-normalizer/internal/normalizer"
	"github.com/vault-csv-normalizer/internal/parser"
	"github.com/vault-csv-normalizer/internal/renderer"
)

// multiFlag allows -f to be specified multiple times.
type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprintf("%v", *m) }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	var inputFiles multiFlag
	var sortBy string
	var filterNS string
	var filterType string
	var countPKI bool
	var noDedup bool
	var showHelp bool

	flag.Var(&inputFiles, "f", "One or more Vault client export CSV files. May be specified multiple times or followed by multiple paths.")
	flag.StringVar(&sortBy, "sort", "namespace_path", "Column to sort by: namespace_path, client_type, token_creation_time, client_first_usage_time, mount_accessor")
	flag.StringVar(&filterNS, "namespace", "", "Filter rows by namespace path (substring match)")
	flag.StringVar(&filterType, "type", "", "Filter rows by client type: entity, non-entity, acme, secret-sync")
	flag.BoolVar(&countPKI, "p", false, "Partition and report PKI clients (auth_method=cert) separately from non-PKI clients")
	flag.BoolVar(&noDedup, "d", false, "Disable deduplication (count duplicate client IDs separately)")
	flag.BoolVar(&showHelp, "help", false, "Show usage information")
	flag.Parse()
	inputFiles = append(inputFiles, flag.Args()...)

	if showHelp || len(inputFiles) == 0 {
		printUsage()
		os.Exit(0)
	}

	// Parse all input files.
	var allRecords []parser.RawRecord
	for _, path := range inputFiles {
		records, err := parser.ParseFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
			os.Exit(1)
		}
		allRecords = append(allRecords, records...)
	}

	if len(allRecords) == 0 {
		fmt.Fprintln(os.Stderr, "no records found across the provided CSV files")
		os.Exit(1)
	}

	// Normalize (and optionally deduplicate) across all input files.
	normalized := normalizer.Normalize(allRecords)
	if !noDedup {
		normalized = normalizer.Deduplicate(normalized)
	}

	// Apply filters.
	if filterNS != "" {
		normalized = normalizer.FilterByNamespace(normalized, filterNS)
	}
	if filterType != "" {
		normalized = normalizer.FilterByClientType(normalized, filterType)
	}

	// Sort.
	if err := normalizer.Sort(normalized, sortBy); err != nil {
		fmt.Fprintf(os.Stderr, "sort error: %v\n", err)
		os.Exit(1)
	}

	if countPKI {
		pkiRecords, nonPKIRecords := normalizer.PartitionPKI(normalized)
		renderer.PrintSummary(os.Stdout, nonPKIRecords, "Non-PKI Client Summary")
		renderer.PrintSummary(os.Stdout, pkiRecords, "PKI Client Summary")
	} else {
		renderer.PrintSummary(os.Stdout, normalized, "")
	}
}

func printUsage() {
	fmt.Println(`vault-csv-normalizer — normalize and display Vault client export CSVs

USAGE:
  vault-csv-normalizer -f <file1.csv> [file2.csv ...] [options]
  vault-csv-normalizer -f <file1.csv> -f <file2.csv> [options]

OPTIONS:`)
	flag.PrintDefaults()
	fmt.Println(`
EXAMPLES:
  # Single file
  vault-csv-normalizer -f export-2024-01.csv

  # Multiple files after one -f flag
  vault-csv-normalizer -f jan.csv feb.csv mar.csv --sort client_type

  # Multiple files with repeated -f flags
  vault-csv-normalizer -f jan.csv -f feb.csv -f mar.csv

  # Filter to a specific namespace
  vault-csv-normalizer -f export.csv --namespace education/

  # Filter to entity clients only
  vault-csv-normalizer -f export.csv --type entity

  # Show PKI clients separately from non-PKI clients
  vault-csv-normalizer -f export.csv -p

  # PKI report across multiple months
  vault-csv-normalizer -f jan.csv feb.csv -p

CSV FORMAT (Vault activity export):
  Expected columns (order-independent, case-insensitive):
    client_id, namespace_id, namespace_path, mount_accessor, mount_path,
    mount_type, auth_method, client_type, token_creation_time,
    client_first_usage_time

  Older Vault exports may use "timestamp" instead of "token_creation_time".
  All variants are handled automatically.

  PKI clients are identified by a mount_accessor that starts with "auth_cert".`)
}
