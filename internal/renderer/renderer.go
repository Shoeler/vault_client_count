// Package renderer formats normalized Vault client records as a pretty-printed
// terminal table and summary footer.
package renderer

import (
	"fmt"
	"io"
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
		header: "First Usage",
		width:  22,
		get: func(r normalizer.Record) string {
			return fmtTime(r.ClientFirstUsageTime)
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

// PrintSummary writes counts broken down by client type with an optional label.
// label is printed as the section header (e.g. "Non-PKI Client Summary").
// Pass an empty label to use the default "Summary" heading.
func PrintSummary(w io.Writer, records []normalizer.Record, label string) {
	if len(records) == 0 {
		return
	}

	if label == "" {
		label = "Summary"
	}

	counts := make(map[string]int)
	for _, r := range records {
		counts[r.ClientType]++
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", label)
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", len(label)))
	fmt.Fprintf(w, "  %-18s %d\n", "Total clients:", len(records))

	typeOrder := []string{"entity", "non-entity", "acme", "secret-sync", "unknown"}
	for _, t := range typeOrder {
		if n, ok := counts[t]; ok {
			fmt.Fprintf(w, "  %-18s %d\n", t+":", n)
			delete(counts, t)
		}
	}
	// Catch any types not in the ordered list.
	for t, n := range counts {
		fmt.Fprintf(w, "  %-18s %d\n", t+":", n)
	}
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
