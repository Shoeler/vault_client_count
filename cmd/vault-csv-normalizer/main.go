package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vault-csv-normalizer/internal/normalizer"
	"github.com/vault-csv-normalizer/internal/parser"
	"github.com/vault-csv-normalizer/internal/renderer"
)

// multiFlag allows a flag to be specified multiple times.
type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprintf("%v", *m) }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// fileDateFlag accepts one or more "filename=date" pairs. Keys are matched
// against both the base name and the full path of each record's Source field.
type fileDateFlag map[string]string

func (f fileDateFlag) String() string { return fmt.Sprintf("%v", map[string]string(f)) }
func (f fileDateFlag) Set(v string) error {
	i := strings.LastIndex(v, "=")
	if i < 1 {
		return fmt.Errorf("expected filename=date, got %q", v)
	}
	f[v[:i]] = v[i+1:]
	return nil
}

func main() {
	var inputFiles multiFlag
	var sortBy string
	var filterNS string
	var filterType string
	var filterSince string
	var filterSinceFile = make(fileDateFlag)
	var countPKI bool
	var dedup bool
	var dedupAlias bool
	var debugMode bool
	var perFile bool
	var showHelp bool

	flag.Var(&inputFiles, "f", "One or more Vault client export CSV files. May be specified multiple times or followed by multiple paths.")
	flag.StringVar(&sortBy, "sort", "namespace_path", "Column to sort by: namespace_path, client_type, token_creation_time, client_first_usage_time, mount_accessor")
	flag.StringVar(&filterNS, "namespace", "", "Filter rows by namespace path (substring match)")
	flag.StringVar(&filterType, "type", "", "Filter rows by client type: entity, non-entity, acme, secret-sync")
	flag.StringVar(&filterSince, "since", "", "Exclude records with a token_creation_time before this value (e.g. 2024-01-01 or 2024-01-01T00:00:00Z)")
	flag.Var(&filterSinceFile, "since-file", "Apply a since filter to one file only: filename=date. May be specified multiple times for different files.")
	flag.BoolVar(&countPKI, "p", false, "Partition and report PKI/cert clients (client_type=acme or mount_accessor prefix auth_cert) separately")
	flag.BoolVar(&dedup, "d", false, "Deduplicate records by client_id across all input files")
	flag.BoolVar(&dedupAlias, "dedup-alias", false, "Deduplicate by entity_alias_name (strips domain and -t0/-t1/-t2 tier suffixes; records without an alias are always kept; may be combined with -d)")
	flag.BoolVar(&debugMode, "debug", false, "Print a table of all records with no mount path")
	flag.BoolVar(&perFile, "per-file", false, "Print a summary for each input file before the combined summary")
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

	// Normalize across all input files.
	normalized := normalizer.Normalize(allRecords)

	// Apply per-file since filters before deduplication so that a record
	// filtered out from one file does not block the same client_id in another.
	if len(filterSinceFile) > 0 {
		sinceByKey := make(map[string]time.Time, len(filterSinceFile))
		for nameKey, dateStr := range filterSinceFile {
			t := normalizer.ParseTime(dateStr)
			if t.IsZero() {
				fmt.Fprintf(os.Stderr, "error: --since-file %q=%q is not a recognized date/time format\n", nameKey, dateStr)
				os.Exit(1)
			}
			sinceByKey[nameKey] = t
		}
		normalized = normalizer.FilterSincePerSource(normalized, sinceByKey)
	}
	if dedupAlias {
		groups := normalizer.FindAliasDuplicates(normalized)
		if len(groups) > 0 {
			fmt.Fprintf(os.Stdout, "Alias duplicates found (%d group(s))\n", len(groups))
			fmt.Fprintln(os.Stdout, "=====================================")
			for _, group := range groups {
				r0 := group[0]
				fmt.Fprintf(os.Stdout, "\nAlias group: %q  file: %s\n",
					normalizer.StripTierSuffix(normalizer.BaseAlias(r0.EntityAliasName)), filepath.Base(r0.Source))
				renderer.PrintTable(os.Stdout, group)
			}
			fmt.Fprintln(os.Stdout)
		}
		normalized = normalizer.DeduplicateByAlias(normalized)
	}
	if dedup {
		normalized = normalizer.Deduplicate(normalized)
	}

	// Apply filters.
	if filterNS != "" {
		normalized = normalizer.FilterByNamespace(normalized, filterNS)
	}
	if filterType != "" {
		normalized = normalizer.FilterByClientType(normalized, filterType)
	}
	if filterSince != "" {
		since := normalizer.ParseTime(filterSince)
		if since.IsZero() {
			fmt.Fprintf(os.Stderr, "error: --since %q is not a recognized date/time format\n", filterSince)
			os.Exit(1)
		}
		normalized = normalizer.FilterSince(normalized, since)
	}

	// Sort.
	if err := normalizer.Sort(normalized, sortBy); err != nil {
		fmt.Fprintf(os.Stderr, "sort error: %v\n", err)
		os.Exit(1)
	}

	if debugMode {
		var noMount []normalizer.Record
		for _, r := range normalized {
			if r.MountPath == "" {
				noMount = append(noMount, r)
			}
		}
		fmt.Fprintf(os.Stdout, "Debug: (no mount) records (%d)\n", len(noMount))
		fmt.Fprintln(os.Stdout, "==================================")
		renderer.PrintTable(os.Stdout, noMount)
		fmt.Fprintln(os.Stdout)
	}

	if perFile {
		bySource := make(map[string][]normalizer.Record, len(inputFiles))
		for _, r := range normalized {
			bySource[r.Source] = append(bySource[r.Source], r)
		}
		for _, path := range inputFiles {
			label := filepath.Base(path)
			fileRecords := bySource[path]
			if countPKI {
				pki, nonPKI := normalizer.PartitionPKI(fileRecords, normalizer.IsPKIClient)
				renderer.PrintSummary(os.Stdout, nonPKI, label+" — Non-PKI")
				renderer.PrintSummary(os.Stdout, pki, label+" — PKI")
			} else {
				renderer.PrintSummary(os.Stdout, fileRecords, label)
			}
		}
	}

	if countPKI {
		pkiRecords, nonPKIRecords := normalizer.PartitionPKI(normalized, normalizer.IsPKIClient)
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

  # Apply --since only to one file (e.g. jan.csv starts mid-month)
  vault-csv-normalizer -f jan.csv feb.csv --since-file jan.csv=2024-01-15

  # Per-file since filters on multiple files
  vault-csv-normalizer -f jan.csv feb.csv --since-file jan.csv=2024-01-15 --since-file feb.csv=2024-02-01

CSV FORMAT (Vault activity export):
  Expected columns (order-independent, case-insensitive):
    client_id, namespace_id, namespace_path, mount_accessor, mount_path,
    mount_type, auth_method, client_type, token_creation_time,
    client_first_usage_time

  Older Vault exports may use "timestamp" instead of "token_creation_time".
  All variants are handled automatically.

  PKI clients are identified by client_type=acme or a mount_accessor that
  starts with "auth_cert" (cert auth method clients).

  Optional column:
    entity_alias_name  (also accepted as: alias_name, entity_alias)
      When present, --dedup-alias collapses records that share the same
      normalized alias in the same source file down to one entry per client,
      regardless of mount accessor. Normalization strips the domain suffix
      (at '@') and any trailing tier suffix (-t0, -t1, -t2). This handles
      the same user authenticating via multiple mounts or tiers.
      Examples: "sbishop", "sbishop-t0", and "sbishop@hashicorp.com" → one client.`)
}
