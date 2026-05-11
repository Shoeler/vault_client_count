package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	var dedupJWT bool
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
	flag.BoolVar(&dedupJWT, "dedup-jwt", false, "Drop JWT records whose normalized alias matches a non-JWT record in the same file (prevents counting the same person via both LDAP/OIDC and JWT)")
	flag.BoolVar(&debugMode, "debug", false, "Print all records grouped by mount path")
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
	// Snapshot pre-dedup records so debug mode can show alias groups from the
	// original data regardless of which dedup flags are active.
	preDedup := normalized
	if dedupAlias {
		groups := normalizer.FindAliasDuplicates(preDedup)
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

	// Collect -d dedup statistics before running so debug mode can report
	// exactly which client_ids were (or weren't) collapsed.
	var clientIDDupsBefore int
	var clientIDDupsAfter int
	var clientIDDupMap map[string]int // client_id → count of input records
	if dedup && debugMode {
		clientIDDupsBefore = len(normalized)
		idCount := make(map[string]int, len(normalized))
		for _, r := range normalized {
			idCount[r.ClientID]++
		}
		clientIDDupMap = make(map[string]int)
		for id, n := range idCount {
			if n > 1 {
				clientIDDupMap[id] = n
			}
		}
	}
	if dedup {
		normalized = normalizer.Deduplicate(normalized)
		if debugMode {
			clientIDDupsAfter = len(normalized)
		}
	}
	if dedupJWT {
		normalized = normalizer.DeduplicateJWT(normalized)
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
		// Show -d dedup results so the user can see which client_ids were (or
		// weren't) collapsed, and understand why records still appear after dedup.
		if dedup {
			collapsed := clientIDDupsBefore - clientIDDupsAfter
			fmt.Fprintf(os.Stdout, "Debug: -d client_id dedup — before: %d  after: %d  collapsed: %d\n",
				clientIDDupsBefore, clientIDDupsAfter, collapsed)
			fmt.Fprintln(os.Stdout, strings.Repeat("-", 70))
			if len(clientIDDupMap) > 0 {
				dupIDs := make([]string, 0, len(clientIDDupMap))
				for id := range clientIDDupMap {
					dupIDs = append(dupIDs, id)
				}
				sort.Strings(dupIDs)
				for _, id := range dupIDs {
					fmt.Fprintf(os.Stdout, "  %s  (x%d → kept 1)\n", id, clientIDDupMap[id])
				}
			} else {
				fmt.Fprintln(os.Stdout, "  (no duplicate client_ids found)")
			}
			fmt.Fprintln(os.Stdout)
		}

		// Show alias groups from the original (pre-dedup) data so the user can
		// see aliasing context regardless of which dedup flags are active.
		// Skip when -dedup-alias is set because it already printed these above.
		if !dedupAlias {
			groups := normalizer.FindAliasDuplicates(preDedup)
			if len(groups) > 0 {
				fmt.Fprintf(os.Stdout, "Debug: alias groups in input data (%d group(s))\n", len(groups))
				fmt.Fprintln(os.Stdout, "===============================================")
				for _, group := range groups {
					r0 := group[0]
					fmt.Fprintf(os.Stdout, "\nAlias group: %q  file: %s\n",
						normalizer.StripTierSuffix(normalizer.BaseAlias(r0.EntityAliasName)), filepath.Base(r0.Source))
					renderer.PrintTable(os.Stdout, group)
				}
				fmt.Fprintln(os.Stdout)
			}
		}

		// Group final (post-dedup) records by mount path.
		var mountOrder []string
		byMount := make(map[string][]normalizer.Record)
		for _, r := range normalized {
			mp := r.MountPath
			if mp == "" {
				mp = "(no mount)"
			}
			if _, seen := byMount[mp]; !seen {
				mountOrder = append(mountOrder, mp)
			}
			byMount[mp] = append(byMount[mp], r)
		}
		fmt.Fprintf(os.Stdout, "Debug: records by mount path (%d mount(s))\n", len(mountOrder))
		fmt.Fprintln(os.Stdout, "==========================================")
		for _, mp := range mountOrder {
			group := byMount[mp]
			fmt.Fprintf(os.Stdout, "\nMount: %s (%d record(s))\n", mp, len(group))
			renderer.PrintTable(os.Stdout, group)
			// Flag records within this mount that share an entity alias but have
			// different client_ids — these are candidates for -dedup-alias.
			if len(group) > 1 {
				aliasToIDs := make(map[string][]string)
				for _, r := range group {
					if r.EntityAliasName == "" {
						continue
					}
					norm := normalizer.StripTierSuffix(normalizer.BaseAlias(r.EntityAliasName))
					aliasToIDs[norm] = append(aliasToIDs[norm], r.ClientID)
				}
				for alias, ids := range aliasToIDs {
					if len(ids) < 2 {
						continue
					}
					// Check that not all client_ids are the same (already handled by -d).
					allSame := true
					for _, id := range ids[1:] {
						if id != ids[0] {
							allSame = false
							break
						}
					}
					if !allSame {
						fmt.Fprintf(os.Stdout, "  !! alias %q has %d records with different client_ids — use -dedup-alias to collapse\n", alias, len(ids))
					}
				}
			}
		}
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
      normalized alias within the same identity group across all input files.
      LDAP and OIDC are treated as one group. Normalization strips the domain
      suffix (at '@') and any trailing tier suffix (-t0, -t1, -t2).
      "sbishop" (LDAP, jan.csv), "sbishop-t0" (LDAP, feb.csv), and
      "sbishop@corp.com" (OIDC) → one client. JWT is a separate group;
      use --dedup-jwt to additionally collapse JWT against LDAP/OIDC.

      --dedup-jwt uses the same normalization to match JWT records against
      non-JWT records in the same file. A JWT record is dropped if a non-JWT
      record (e.g. LDAP or OIDC) shares the same normalized alias, preventing
      the same person from being counted twice when they authenticate via both
      methods. Can be combined with --dedup-alias and/or -d.`)
}
