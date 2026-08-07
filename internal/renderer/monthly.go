package renderer

import (
	"fmt"
	"io"
	"math"
	"sort"
	"time"

	"github.com/vault-csv-normalizer/internal/normalizer"
)

// WriteMonthlyTSV writes a three-column tab-separated file with a header row:
//
//	YYYY-MM-DD  <entitlement>  <cumulative total>
//
// Each row represents one calendar month. The date is the first day of that
// month. The cumulative total is the running sum of all client records through
// and including that month. Records with a zero TokenCreationTime are skipped
// because they cannot be assigned a date. The header row is always written,
// even when there are no data rows.
func WriteMonthlyTSV(w io.Writer, records []normalizer.Record, entitlement int) {
	fmt.Fprintf(w, "date\tentitlement\tcumulative_total\n")

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

// WriteMonthlyTSVPartitioned writes a four-column tab-separated file with a
// header row:
//
//	YYYY-MM-DD  <entitlement>  <non-PKI cumulative total>  <PKI cumulative total>
//
// It behaves like WriteMonthlyTSV but splits each month's count into PKI and
// non-PKI columns using normalizer.IsPKIClient, each tracked as its own
// running cumulative total. Records with a zero TokenCreationTime are
// skipped because they cannot be assigned a date. The header row is always
// written, even when there are no data rows.
func WriteMonthlyTSVPartitioned(w io.Writer, records []normalizer.Record, entitlement int) {
	fmt.Fprintf(w, "date\tentitlement\tnon_pki_cumulative_total\tpki_cumulative_total\n")

	nonPKICounts := make(map[string]int) // "YYYY-MM" → non-PKI count for that month
	pkiCounts := make(map[string]int)    // "YYYY-MM" → PKI count for that month

	for _, r := range records {
		if r.TokenCreationTime.IsZero() {
			continue
		}
		month := r.TokenCreationTime.UTC().Format("2006-01")
		if normalizer.IsPKIClient(r) {
			pkiCounts[month]++
		} else {
			nonPKICounts[month]++
		}
	}

	monthSet := make(map[string]struct{}, len(nonPKICounts)+len(pkiCounts))
	for m := range nonPKICounts {
		monthSet[m] = struct{}{}
	}
	for m := range pkiCounts {
		monthSet[m] = struct{}{}
	}
	months := make([]string, 0, len(monthSet))
	for m := range monthSet {
		months = append(months, m)
	}
	sort.Strings(months)

	nonPKIRunning, pkiRunning := 0, 0
	for _, m := range months {
		nonPKIRunning += nonPKICounts[m]
		pkiRunning += pkiCounts[m]
		date := m + "-01"
		fmt.Fprintf(w, "%s\t%d\t%d\t%d\n", date, entitlement, nonPKIRunning, pkiRunning)
	}
}

// WriteMonthlyTSVSoko writes a three-column tab-separated file with no header
// row:
//
//	YYYY-MM-DD  <entitlement>  <total clients>
//
// The date is the last day of the month (not the first, as in WriteMonthlyTSV
// and WriteMonthlyTSVPartitioned). The total is a running cumulative count.
// If countPKI is true, PKI clients (normalizer.IsPKIClient) are tracked
// separately from non-PKI clients and folded into the total as
// non-PKI + round(PKI / 40); if false, all records count toward the total
// directly, as in WriteMonthlyTSV. Records with a zero TokenCreationTime are
// skipped because they cannot be assigned a date.
func WriteMonthlyTSVSoko(w io.Writer, records []normalizer.Record, entitlement int, countPKI bool) {
	nonPKICounts := make(map[string]int) // "YYYY-MM" → non-PKI count for that month
	pkiCounts := make(map[string]int)    // "YYYY-MM" → PKI count for that month

	for _, r := range records {
		if r.TokenCreationTime.IsZero() {
			continue
		}
		month := r.TokenCreationTime.UTC().Format("2006-01")
		if countPKI && normalizer.IsPKIClient(r) {
			pkiCounts[month]++
		} else {
			nonPKICounts[month]++
		}
	}

	monthSet := make(map[string]struct{}, len(nonPKICounts)+len(pkiCounts))
	for m := range nonPKICounts {
		monthSet[m] = struct{}{}
	}
	for m := range pkiCounts {
		monthSet[m] = struct{}{}
	}
	months := make([]string, 0, len(monthSet))
	for m := range monthSet {
		months = append(months, m)
	}
	sort.Strings(months)

	nonPKIRunning, pkiRunning := 0, 0
	for _, m := range months {
		nonPKIRunning += nonPKICounts[m]
		pkiRunning += pkiCounts[m]

		total := nonPKIRunning
		if countPKI {
			total = nonPKIRunning + int(math.Round(float64(pkiRunning)/40))
		}

		t, err := time.Parse("2006-01", m)
		if err != nil {
			panic(err) // m is always produced by our own Format("2006-01") call above
		}
		date := t.AddDate(0, 1, -1).Format("2006-01-02") // last day of month m

		fmt.Fprintf(w, "%s\t%d\t%d\n", date, entitlement, total)
	}
}
