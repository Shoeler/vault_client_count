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
	"github.com/vault-csv-normalizer/internal/tfgen"
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

// collectPositionalFiles returns the file arguments left over after fs has been
// parsed. Go's flag package stops at the first positional argument, so a file
// list followed by more options ("-f *.csv -d", once the shell has expanded the
// wildcard) would otherwise treat "-d" as a filename. Each time a flag follows a
// run of files, parsing resumes from that flag. Everything after a "--"
// terminator is taken as a file.
func collectPositionalFiles(fs *flag.FlagSet) ([]string, error) {
	var files []string
	for args := fs.Args(); len(args) > 0; args = fs.Args() {
		n := 0
		for n < len(args) && !isFlagArg(args[n]) {
			n++
		}
		if n == 0 {
			// Parse only leaves a flag-like argument first when it follows "--".
			return append(files, args...), nil
		}
		files = append(files, args[:n]...)
		if n == len(args) {
			break
		}
		if err := fs.Parse(args[n:]); err != nil {
			return nil, err
		}
	}
	return files, nil
}

// isFlagArg reports whether the flag package would treat arg as a flag (or the
// "--" terminator) rather than a positional argument. A bare "-" is positional.
func isFlagArg(arg string) bool {
	return len(arg) > 1 && arg[0] == '-'
}

// expandInputFiles resolves wildcard patterns (*, ?, [...]) in the input file
// list, so a quoted pattern such as -f 'exports/*.csv' behaves the same as one
// expanded by the shell. Matches are added in sorted order per pattern, and
// directories matched by a pattern are skipped. A path that is already in the
// list is not added again, so overlapping patterns do not read a file twice.
// A pattern that matches no files is an error.
func expandInputFiles(patterns []string) (multiFlag, error) {
	var files multiFlag
	seen := make(map[string]bool)
	add := func(path string) {
		key := filepath.Clean(path)
		if !seen[key] {
			seen[key] = true
			files = append(files, path)
		}
	}
	for _, pattern := range patterns {
		if !strings.ContainsAny(pattern, "*?[") {
			add(pattern)
			continue
		}
		// A file whose name literally contains wildcard characters wins.
		if _, err := os.Stat(pattern); err == nil {
			add(pattern)
			continue
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid file pattern %q: %v", pattern, err)
		}
		matched := 0
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil && info.IsDir() {
				continue
			}
			add(m)
			matched++
		}
		if matched == 0 {
			return nil, fmt.Errorf("no files match pattern %q", pattern)
		}
	}
	return files, nil
}

// tfOutputPath is the file --generate-tf writes, relative to the working directory.
const tfOutputPath = "vault-aliases.tf"

func main() {
	var inputFiles multiFlag
	var dedupMethods multiFlag
	var dedupMethodsPerFile multiFlag
	var sortBy string
	var filterNS string
	var filterType string
	var filterSince string
	var filterSinceFile = make(fileDateFlag)
	var countPKI bool
	var dedup bool
	var dedupAlias bool
	var dedupJWT bool
	var removeAbandonedClients bool
	var generateTF bool
	var listMethods bool
	var debugMode bool
	var perFile bool
	var showHelp bool
	var monthlyOutput string
	var monthlyEntitlement int
	var monthlySoko bool

	flag.Var(&inputFiles, "f", "One or more Vault client export CSV files. May be specified multiple times or followed by multiple paths. Wildcard patterns (*, ?, [...]) are expanded; quote a pattern to have the tool expand it instead of the shell.")
	flag.StringVar(&sortBy, "sort", "namespace_path", "Column to sort by: namespace_path, client_type, token_creation_time, client_first_usage_time, mount_accessor, mount_path, auth_method, source")
	flag.StringVar(&filterNS, "namespace", "", "Filter rows by namespace path (substring match)")
	flag.StringVar(&filterType, "type", "", "Filter rows by client type: entity, non-entity, acme, secret-sync")
	flag.StringVar(&filterSince, "since", "", "Exclude records with a token_creation_time before this value (e.g. 2024-01-01 or 2024-01-01T00:00:00Z)")
	flag.Var(&filterSinceFile, "since-file", "Apply a since filter to one file only: filename=date. May be specified multiple times for different files.")
	flag.BoolVar(&countPKI, "p", false, "Partition and report PKI/cert clients (client_type=acme or mount_accessor prefix auth_cert) separately")
	flag.BoolVar(&dedup, "d", false, "Deduplicate records by client_id across all input files")
	flag.BoolVar(&dedupAlias, "dedup-alias", false, "Deduplicate by entity_alias_name (strips domain and -t0/-t1/-t2 tier suffixes; records without an alias are always kept; may be combined with -d)")
	flag.Var(&dedupMethods, "dedup-methods", "Deduplicate by alias for the specified comma-separated auth methods, treating them as one identity group. Repeatable to define multiple groups (e.g. -dedup-methods ldap,oidc -dedup-methods jwt,saml).")
	flag.Var(&dedupMethodsPerFile, "dedup-methods-per-file", "Like --dedup-methods but scoped to each input file independently. Records in different files are never collapsed against each other. Repeatable to define multiple groups.")
	flag.BoolVar(&dedupJWT, "dedup-jwt", false, "Drop JWT records whose normalized alias matches a non-JWT record in any input file (prevents counting the same person via both LDAP/OIDC and JWT)")
	flag.BoolVar(&removeAbandonedClients, "remove-abandoned-clients", false, "Remove abandoned entity clients (client_type entity with blank entity_name and entity_alias_name) after deduplication; other client types are never removed. Includes records with no auth mount and merged/deleted entities.")
	flag.BoolVar(&generateTF, "generate-tf", false, "Write Terraform HCL to "+tfOutputPath+" that consolidates each --dedup-methods-per-file alias duplicate group into one vault_identity_entity with one vault_identity_entity_alias per record. Requires --dedup-methods-per-file. Does not change counts or summary output.")
	flag.BoolVar(&listMethods, "list-methods", false, "Print every distinct auth method found in the input files (with record counts and alias coverage), then exit. Useful for deciding --dedup-methods groups.")
	flag.BoolVar(&debugMode, "debug", false, "Print all records grouped by mount path")
	flag.BoolVar(&perFile, "per-file", false, "Print a summary for each input file before the combined summary")
	flag.BoolVar(&showHelp, "help", false, "Show usage information")
	flag.StringVar(&monthlyOutput, "monthly-output", "", "Write month-by-month client counts as a tab-separated file to this path (useful for trend forecasting); with -p, splits each row into separate non-PKI and PKI cumulative columns")
	flag.IntVar(&monthlyEntitlement, "monthly-entitlement", 0, "License entitlement count to include in each row of the monthly output (prompted interactively if not provided)")
	flag.BoolVar(&monthlySoko, "soko", false, "With -monthly-output, write a headerless three-column file (end-of-month date, entitlement, total clients); with -p, PKI clients are divided by 40, rounded, and folded into the total")
	flag.Parse()
	positional, err := collectPositionalFiles(flag.CommandLine)
	if err != nil {
		// flag.CommandLine exits on parse errors, so this is not reached in practice.
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	inputFiles = append(inputFiles, positional...)

	if showHelp || len(inputFiles) == 0 {
		printUsage()
		os.Exit(0)
	}

	inputFiles, err = expandInputFiles(inputFiles)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := validateSinceFileKeys(sinceFileKeys(filterSinceFile), inputFiles); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if generateTF && len(dedupMethodsPerFile) == 0 {
		fmt.Fprintln(os.Stderr, "error: --generate-tf requires --dedup-methods-per-file")
		os.Exit(1)
	}

	entitlementProvided := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "monthly-entitlement" {
			entitlementProvided = true
		}
	})
	if monthlyOutput == "" && (monthlySoko || entitlementProvided) {
		fmt.Fprintln(os.Stderr, "warning: -soko and -monthly-entitlement have no effect without -monthly-output")
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
	if listMethods {
		printMethodList(normalized, inputFiles)
		os.Exit(0)
	}

	// Parse --dedup-methods values into groups. Each flag value is a
	// comma-separated list of mount types that form one identity group.
	var methodGroups [][]string
	for _, val := range dedupMethods {
		var group []string
		for _, m := range strings.Split(val, ",") {
			m = strings.TrimSpace(strings.ToLower(m))
			if m != "" {
				group = append(group, m)
			}
		}
		if len(group) > 0 {
			methodGroups = append(methodGroups, group)
		}
	}

	var methodGroupsPerFile [][]string
	for _, val := range dedupMethodsPerFile {
		var group []string
		for _, m := range strings.Split(val, ",") {
			m = strings.TrimSpace(strings.ToLower(m))
			if m != "" {
				group = append(group, m)
			}
		}
		if len(group) > 0 {
			methodGroupsPerFile = append(methodGroupsPerFile, group)
		}
	}

	// Order records by token creation time (undated records last) so that the
	// "first occurrence" kept by every dedup step below is the earliest dated
	// one rather than whichever file happened to be listed first. This keeps
	// the monthly cumulative curve from shifting later when files are given in
	// non-chronological order.
	sort.SliceStable(normalized, func(i, j int) bool {
		a, b := normalized[i].TokenCreationTime, normalized[j].TokenCreationTime
		if a.IsZero() || b.IsZero() {
			return !a.IsZero() && b.IsZero()
		}
		return a.Before(b)
	})

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
	if len(methodGroups) > 0 {
		groups := normalizer.FindAliasDuplicatesForMethods(preDedup, methodGroups)
		if len(groups) > 0 {
			fmt.Fprintf(os.Stdout, "Method-scoped alias duplicates found (%d group(s))\n", len(groups))
			fmt.Fprintln(os.Stdout, "================================================")
			for _, group := range groups {
				r0 := group[0]
				fmt.Fprintf(os.Stdout, "\nAlias group: %q  file: %s\n",
					normalizer.StripTierSuffix(normalizer.BaseAlias(r0.EntityAliasName)), filepath.Base(r0.Source))
				renderer.PrintTable(os.Stdout, group)
			}
			fmt.Fprintln(os.Stdout)
		}
		normalized = normalizer.DeduplicateByAliasForMethods(normalized, methodGroups)
	}
	// Per-file alias duplicate groups are kept for --generate-tf, which turns
	// each group into one Terraform entity with an alias per record.
	var perFileAliasGroups [][]normalizer.Record
	if len(methodGroupsPerFile) > 0 {
		perFileAliasGroups = normalizer.FindAliasDuplicatesForMethodsPerFile(preDedup, methodGroupsPerFile)
		if len(perFileAliasGroups) > 0 {
			fmt.Fprintf(os.Stdout, "Per-file method-scoped alias duplicates found (%d group(s))\n", len(perFileAliasGroups))
			fmt.Fprintln(os.Stdout, "=====================================================")
			for _, group := range perFileAliasGroups {
				r0 := group[0]
				fmt.Fprintf(os.Stdout, "\nAlias group: %q  file: %s\n",
					normalizer.PerFileAliasKey(r0), filepath.Base(r0.Source))
				renderer.PrintTable(os.Stdout, group)
			}
			fmt.Fprintln(os.Stdout)
		}
		normalized = normalizer.DeduplicateByAliasForMethodsPerFile(normalized, methodGroupsPerFile)
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

	removedAbandonedCounts := normalizer.AbandonedClientCounts{}
	if removeAbandonedClients {
		normalized, removedAbandonedCounts = normalizer.FilterAbandonedClients(normalized)

		fmt.Fprintf(os.Stdout, "Removed abandoned clients (total): %d\n", removedAbandonedCounts.Total())
		fmt.Fprintf(os.Stdout, "  no auth mount (mount path empty): %d  (PKI: %d, non-PKI: %d)\n",
			removedAbandonedCounts.NoMount, removedAbandonedCounts.NoMountPKI, removedAbandonedCounts.NoMount-removedAbandonedCounts.NoMountPKI)
		fmt.Fprintf(os.Stdout, "  merged/deleted (mount path present): %d  (PKI: %d, non-PKI: %d)\n",
			removedAbandonedCounts.MergedDeleted, removedAbandonedCounts.MergedDeletedPKI, removedAbandonedCounts.MergedDeleted-removedAbandonedCounts.MergedDeletedPKI)
		fmt.Fprintln(os.Stdout, strings.Repeat("-", 70))
	}

	// Generate Terraform after dedup and abandoned-client removal but before the
	// namespace/type/since filters, so the output covers every duplicate group
	// regardless of which rows are displayed. Counts are not affected.
	if generateTF {
		n, err := tfgen.GenerateTF(perFileAliasGroups, tfOutputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: --generate-tf: %v\n", err)
			os.Exit(1)
		}
		if n == 0 {
			fmt.Fprintf(os.Stdout, "generate-tf: no per-file alias duplicate groups found; %s not written\n", tfOutputPath)
		} else {
			fmt.Fprintf(os.Stdout, "generate-tf: wrote %d entity stub(s) to %s\n", n, tfOutputPath)
		}
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

	if (perFile || len(methodGroupsPerFile) > 0) && len(inputFiles) > 1 {
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

	// The monthly output runs last so that a failure here (missing entitlement,
	// unwritable path) never suppresses the summaries above.
	if monthlyOutput != "" {
		if !entitlementProvided {
			if !stdinIsTerminal() {
				fmt.Fprintln(os.Stderr, "error: -monthly-entitlement is required when stdin is not a terminal")
				os.Exit(1)
			}
			fmt.Fprint(os.Stderr, "Enter entitlement value: ")
			if _, err := fmt.Scan(&monthlyEntitlement); err != nil {
				fmt.Fprintf(os.Stderr, "error reading entitlement: %v\n", err)
				os.Exit(1)
			}
		}
		f, err := os.Create(monthlyOutput)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error creating monthly output file: %v\n", err)
			os.Exit(1)
		}
		var skipped int
		var writeErr error
		switch {
		case monthlySoko:
			skipped, writeErr = renderer.WriteMonthlyTSVSoko(f, normalized, monthlyEntitlement, countPKI)
		case countPKI:
			skipped, writeErr = renderer.WriteMonthlyTSVPartitioned(f, normalized, monthlyEntitlement)
		default:
			skipped, writeErr = renderer.WriteMonthlyTSV(f, normalized, monthlyEntitlement)
		}
		closeErr := f.Close()
		if writeErr != nil {
			fmt.Fprintf(os.Stderr, "error writing monthly output file: %v\n", writeErr)
			os.Exit(1)
		}
		if closeErr != nil {
			fmt.Fprintf(os.Stderr, "error closing monthly output file: %v\n", closeErr)
			os.Exit(1)
		}
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, "warning: %d record(s) with no token_creation_time omitted from monthly output\n", skipped)
		}
		fmt.Fprintf(os.Stdout, "Monthly counts written to %s\n", monthlyOutput)
	}
}

// stdinIsTerminal reports whether standard input is an interactive terminal.
func stdinIsTerminal() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	// /dev/null is also a character device but is not interactive.
	if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(info, null) {
		return false
	}
	return true
}

// sinceFileKeys returns the filename keys of a --since-file flag value.
func sinceFileKeys(f fileDateFlag) []string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// validateSinceFileKeys checks that every --since-file key matches the base
// name or the full path of at least one input file. A key that matches nothing
// would otherwise be ignored silently, leaving counts unfiltered.
func validateSinceFileKeys(keys []string, files []string) error {
	for _, key := range keys {
		matched := false
		for _, file := range files {
			if key == file || key == filepath.Base(file) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("--since-file %q does not match any input file", key)
		}
	}
	return nil
}

func printMethodList(records []normalizer.Record, files []string) {
	type methodStats struct {
		total     int
		withAlias int
	}
	stats := make(map[string]*methodStats)
	order := []string{}

	for _, r := range records {
		mt := r.MountType
		if mt == "" {
			mt = r.AuthMethod
		}
		if mt == "" {
			mt = "(blank)"
		}
		s, ok := stats[mt]
		if !ok {
			s = &methodStats{}
			stats[mt] = s
			order = append(order, mt)
		}
		s.total++
		if r.EntityAliasName != "" {
			s.withAlias++
		}
	}
	sort.Strings(order)

	fmt.Fprintf(os.Stdout, "Auth methods in input data (%d file(s), %d record(s))\n", len(files), len(records))
	fmt.Fprintln(os.Stdout, strings.Repeat("=", 55))
	fmt.Fprintf(os.Stdout, "  %-20s  %8s  %10s\n", "Method", "Records", "With Alias")
	fmt.Fprintf(os.Stdout, "  %-20s  %8s  %10s\n", strings.Repeat("-", 20), strings.Repeat("-", 8), strings.Repeat("-", 10))
	for _, mt := range order {
		s := stats[mt]
		fmt.Fprintf(os.Stdout, "  %-20s  %8d  %10d\n", mt, s.total, s.withAlias)
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Tip: use --dedup-methods to group methods into human/machine identity sets.")
	fmt.Fprintln(os.Stdout, "  Example: --dedup-methods ldap,oidc,jwt --dedup-methods approle,kubernetes")
}

func printUsage() {
	fmt.Println(`vault-csv-normalizer — normalize and display Vault client export CSVs

USAGE:
  vault-csv-normalizer -f <file1.csv> [file2.csv ...] [options]
  vault-csv-normalizer -f <file1.csv> -f <file2.csv> [options]
  vault-csv-normalizer -f '<pattern>' [options]

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

  # Wildcard file list (expanded by the shell, or by the tool when quoted)
  vault-csv-normalizer -f exports/*.csv -d
  vault-csv-normalizer -f 'exports/2024-*.csv' -d

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

  # Remove abandoned clients (entity clients with blank entity fields)
  vault-csv-normalizer -f export.csv --remove-abandoned-clients

CSV FORMAT (Vault activity export):
  Expected columns (order-independent, case-insensitive):
    client_id, namespace_id, namespace_path, mount_accessor, mount_path,
    mount_type, auth_method, client_type, token_creation_time,
    client_first_usage_time

  Older Vault exports may use "timestamp" instead of "token_creation_time",
  and some versions emit "client_first_used_time" for "client_first_usage_time".
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
      non-JWT records across all input files. A JWT record is dropped if a non-JWT
      record (e.g. LDAP or OIDC) shares the same normalized alias, preventing
      the same person from being counted twice when they authenticate via both
      methods. Can be combined with --dedup-alias and/or -d.

  --dedup-methods <method1,method2,...>
      Apply alias deduplication (same normalization as --dedup-alias) but only
      for records whose auth method appears in the specified comma-separated
      group. Methods in the same group are treated as one identity — a person
      authenticating via any of them is counted once. Records whose auth method
      is not in any group pass through unchanged.

      The flag is repeatable; each use defines one independent group:

        --dedup-methods ldap,oidc
            Deduplicate LDAP and OIDC as one identity group. "alice" (LDAP),
            "alice@corp.com" (OIDC), and "alice-t0" (LDAP) all normalize to
            "alice" and are counted once.

        --dedup-methods ldap,oidc,jwt
            Treat LDAP, OIDC, and JWT together as one group.

        --dedup-methods ldap,oidc --dedup-methods jwt,saml
            Two independent groups: {ldap,oidc} and {jwt,saml}. A person
            appearing in both LDAP and OIDC is counted once; a person
            appearing in both JWT and SAML is counted once; but an LDAP
            record and a JWT record for the same person are not collapsed
            (unless both groups are merged into one).

      Can be combined with --dedup-alias, --dedup-jwt, and/or -d.

  --dedup-methods-per-file <method1,method2,...>
      Like --dedup-methods but deduplication is scoped to each input file
      independently. Records in different files with the same normalized alias
      are NOT collapsed against each other — only within-file duplicates are
      removed. Useful when files represent different billing periods and you
      want to count a returning user once per file rather than once globally.

      Uses the same method-grouping syntax as --dedup-methods (repeatable,
      comma-separated groups). Alias normalization differs: only the domain
      suffix (at '@') is stripped; tier suffixes (-t0/-t1/-t2) must match
      exactly. OIDC records match on entity_alias_metadata.username when present.

        --dedup-methods-per-file ldap,oidc
            Within each file, collapse LDAP and OIDC records that share the
            same alias (exact match; tier suffixes like -t0/-t1 are distinct).
            A user in jan.csv (LDAP) and feb.csv (OIDC) is NOT collapsed —
            they appear once per file.

        --dedup-methods-per-file ldap,oidc --dedup-methods-per-file jwt,saml
            Two independent per-file groups, each applied strictly within each
            source file.

      Can be combined with --dedup-methods, --dedup-alias, --dedup-jwt, and/or -d.

  --generate-tf
      Requires --dedup-methods-per-file. Writes vault-aliases.tf in the current
      directory. Each per-file alias duplicate group (the groups printed under
      "Per-file method-scoped alias duplicates found") becomes one
      vault_identity_entity named after the shared alias, plus one
      vault_identity_entity_alias per record in the group, linked by
      canonical_id. Mount accessors are emitted as Terraform variables, and
      resources use petnames (e.g. amber_bear) as identifiers. An alias with no
      mount_accessor in the export gets a "TODO" placeholder. Review the file
      before applying. Counts and summary output are unchanged.

        vault-csv-normalizer -f jan.csv --dedup-methods-per-file ldap,oidc --generate-tf`)
}
