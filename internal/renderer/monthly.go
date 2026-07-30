package renderer

import (
	"fmt"
	"io"
	"sort"

	"github.com/vault-csv-normalizer/internal/normalizer"
)

// WriteMonthlyTSV writes a three-column tab-separated file with no header row:
//
//	YYYY-MM-DD  <entitlement>  <cumulative total>
//
// Each row represents one calendar month. The date is the first day of that
// month. The cumulative total is the running sum of all client records through
// and including that month. Records with a zero TokenCreationTime are skipped
// because they cannot be assigned a date.
func WriteMonthlyTSV(w io.Writer, records []normalizer.Record, entitlement int) {
	monthlyCounts := make(map[string]int) // "YYYY-MM" → count for that month

	for _, r := range records {
		if r.TokenCreationTime.IsZero() {
			continue
		}
		month := r.TokenCreationTime.UTC().Format("2006-01")
		monthlyCounts[month]++
	}

	months := make([]string, 0, len(monthlyCounts))
	for m := range monthlyCounts {
		months = append(months, m)
	}
	sort.Strings(months)

	running := 0
	for _, m := range months {
		running += monthlyCounts[m]
		date := m + "-01"
		fmt.Fprintf(w, "%s\t%d\t%d\n", date, entitlement, running)
	}
}
