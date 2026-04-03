// Package renderer formats normalized Vault client records as a pretty-printed
// terminal table and summary footer.
package renderer

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vault-csv-normalizer/internal/normalizer"
)

// column describes a single output column.
type column struct {
	header string
	width  int // minimum width (grows to fit content)
	get    func(r normalizer.Record) string
}

var columns = []column{
	{
		header: "Namespace Path",
		width:  16,
		get:    func(r normalizer.Record) string { return r.NamespacePath },
	},
	{
		header: "Client Type",
		width:  12,
		get:    func(r normalizer.Record) string { return r.ClientType },
	},
	{
		header: "Auth Method",
		width:  12,
		get:    func(r normalizer.Record) string { return r.AuthMethod },
	},
	{
		header: "Mount Path",
		width:  12,
		get:    func(r normalizer.Record) string { return r.MountPath },
	},
	{
		header: "Token Created",
		width:  22,
		get: func(r normalizer.Record) string {
			return fmtTime(r.TokenCreationTime)
		},
	},
	{
		header: "Client ID",
		width:  36,
		get:    func(r normalizer.Record) string { return r.ClientID },
	},
	{
		header: "Source File",
		width:  12,
		get:    func(r normalizer.Record) string { return shortPath(r.Source) },
	},
}

// PrintTable writes the records as a plain-text table to w.
func PrintTable(w io.Writer, records []normalizer.Record) {
	if len(records) == 0 {
		fmt.Fprintln(w, "(no records to display)")
		return
	}

	// Clone columns and compute actual widths.
	cols := make([]column, len(columns))
	copy(cols, columns)

	for _, r := range records {
		for i, c := range cols {
			v := c.get(r)
			if l := utf8.RuneCountInString(v); l > cols[i].width {
				cols[i].width = l
			}
		}
	}

	// Print header.
	printRow(w, cols, func(c column) string { return c.header })
	printSeparator(w, cols)

	// Print data rows.
	for _, r := range records {
		r := r
		printRow(w, cols, func(c column) string { return c.get(r) })
	}
}

// mountStat holds per-client-type counts for one mount path.
type mountStat struct {
	path       string
	typeCounts map[string]int
	total      int
}

// PrintSummary writes a breakdown by mount path (then by client type within
// each mount) followed by a grand total. label is the section header;
// pass "" to use the default "Summary" heading.
func PrintSummary(w io.Writer, records []normalizer.Record, label string) {
	if len(records) == 0 {
		return
	}

	if label == "" {
		label = "Summary"
	}

	// Aggregate: mount path → client type → count.
	statMap := make(map[string]*mountStat)
	for _, r := range records {
		mp := r.MountPath
		if mp == "" {
			mp = "(no mount)"
		}
		ms, ok := statMap[mp]
		if !ok {
			ms = &mountStat{path: mp, typeCounts: make(map[string]int)}
			statMap[mp] = ms
		}
		ms.typeCounts[r.ClientType]++
		ms.total++
	}

	// Sort mount paths alphabetically.
	mountPaths := make([]string, 0, len(statMap))
	for mp := range statMap {
		mountPaths = append(mountPaths, mp)
	}
	sort.Strings(mountPaths)

	// Compute column widths.
	mountColW := len("Mount Path")
	for _, mp := range mountPaths {
		if l := utf8.RuneCountInString(mp); l > mountColW {
			mountColW = l
		}
	}
	typeColW := len("Client Type")
	countColW := len("Count")

	typeOrder := []string{"entity", "non-entity", "acme", "secret-sync", "unknown"}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", label)
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", len(label)))

	// Header row.
	fmt.Fprintf(w, "  %-*s  %-*s  %s\n", mountColW, "Mount Path", typeColW, "Client Type", "Count")
	fmt.Fprintf(w, "  %s  %s  %s\n",
		strings.Repeat("-", mountColW),
		strings.Repeat("-", typeColW),
		strings.Repeat("-", countColW),
	)

	// Data rows — one group per mount path.
	for i, mp := range mountPaths {
		ms := statMap[mp]

		// Print known types in order, then any remaining unknown types.
		remaining := make(map[string]int, len(ms.typeCounts))
		for k, v := range ms.typeCounts {
			remaining[k] = v
		}

		firstRow := true
		printMountRow := func(clientType string, count int) {
			mountLabel := ""
			if firstRow {
				mountLabel = mp
				firstRow = false
			}
			fmt.Fprintf(w, "  %-*s  %-*s  %d\n", mountColW, mountLabel, typeColW, clientType, count)
		}

		for _, t := range typeOrder {
			if n, ok := remaining[t]; ok {
				printMountRow(t, n)
				delete(remaining, t)
			}
		}
		for _, t := range sortedKeys(remaining) {
			printMountRow(t, remaining[t])
		}

		// Subtotal for this mount.
		fmt.Fprintf(w, "  %-*s  %-*s  %d\n", mountColW, "", typeColW, "subtotal:", ms.total)

		// Blank line between mount groups, not after the last one.
		if i < len(mountPaths)-1 {
			fmt.Fprintln(w)
		}
	}

	// Grand total.
	fmt.Fprintf(w, "  %s  %s  %s\n",
		strings.Repeat("-", mountColW),
		strings.Repeat("-", typeColW),
		strings.Repeat("-", countColW),
	)
	fmt.Fprintf(w, "  %-*s  %-*s  %d\n", mountColW, "", typeColW, "TOTAL:", len(records))
}

// sortedKeys returns the keys of m in sorted order.
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// PrintPKIReport prints the PKI client table followed by its summary section.
// Call this only when -p is active and pki is non-empty.
func PrintPKIReport(w io.Writer, pki []normalizer.Record) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "PKI (cert) Clients")
	fmt.Fprintln(w, strings.Repeat("=", 18))

	if len(pki) == 0 {
		fmt.Fprintln(w, "(no PKI clients found)")
		return
	}

	PrintTable(w, pki)
	PrintSummary(w, pki, "PKI Client Summary")
}

// ── helpers ──────────────────────────────────────────────────────────────────

func printRow(w io.Writer, cols []column, value func(column) string) {
	var sb strings.Builder
	for i, c := range cols {
		v := value(c)
		pad := c.width - utf8.RuneCountInString(v)
		if pad < 0 {
			pad = 0
		}
		if i > 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(v)
		sb.WriteString(strings.Repeat(" ", pad))
	}
	fmt.Fprintln(w, strings.TrimRight(sb.String(), " "))
}

func printSeparator(w io.Writer, cols []column) {
	var sb strings.Builder
	for i, c := range cols {
		if i > 0 {
			sb.WriteString("  ")
		}
		sb.WriteString(strings.Repeat("-", c.width))
	}
	fmt.Fprintln(w, sb.String())
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

// shortPath returns just the filename component of a path for display.
func shortPath(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[i+1:]
		}
	}
	return path
}
