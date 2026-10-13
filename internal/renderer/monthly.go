package renderer

import (
	"fmt"
	"io"
	"math"
	"time"

	"github.com/vault-csv-normalizer/internal/normalizer"
)

// monthlyRow is one calendar month of cumulative counts.
type monthlyRow struct {
	month  time.Time // first day of the month, UTC
	nonPKI int       // cumulative non-PKI count through this month
	pki    int       // cumulative PKI count through this month
}

// buildMonthlyRows buckets records by the calendar month of TokenCreationTime
// and returns one row per month from the earliest to the latest month seen,
// in chronological order. Months with no records carry the previous
// cumulative totals forward. isPKI decides which records count as PKI; a nil
// isPKI counts every record as non-PKI. The second return value is the number
// of records skipped because their TokenCreationTime is zero.
func buildMonthlyRows(records []normalizer.Record, isPKI func(normalizer.Record) bool) ([]monthlyRow, int) {
	type counts struct{ nonPKI, pki int }
	byMonth := make(map[time.Time]*counts)
	var first, last time.Time
	skipped := 0

	for _, r := range records {
		if r.TokenCreationTime.IsZero() {
			skipped++
			continue
		}
		t := r.TokenCreationTime.UTC()
		m := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		c, ok := byMonth[m]
		if !ok {
			c = &counts{}
			byMonth[m] = c
		}
		if isPKI != nil && isPKI(r) {
			c.pki++
		} else {
			c.nonPKI++
		}
		if first.IsZero() || m.Before(first) {
			first = m
		}
		if last.IsZero() || m.After(last) {
			last = m
		}
	}

	if len(byMonth) == 0 {
		return nil, skipped
	}

	var rows []monthlyRow
	nonPKIRunning, pkiRunning := 0, 0
	for m := first; !m.After(last); m = m.AddDate(0, 1, 0) {
		if c, ok := byMonth[m]; ok {
			nonPKIRunning += c.nonPKI
			pkiRunning += c.pki
		}
		rows = append(rows, monthlyRow{month: m, nonPKI: nonPKIRunning, pki: pkiRunning})
	}
	return rows, skipped
}

// errWriter remembers the first error returned by the underlying writer and
// ignores later writes.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, args ...interface{}) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

// WriteMonthlyTSV writes a three-column tab-separated file with a header row:
//
//	YYYY-MM-DD  <entitlement>  <cumulative total>
//
// Each row represents one calendar month, from the earliest to the latest
// month present in records; months with no records repeat the previous
// cumulative total. The date is the first day of that month. The cumulative
// total is the running sum of all client records through and including that
// month. Records with a zero TokenCreationTime cannot be assigned a date and
// are skipped; their number is returned. The header row is always written,
// even when there are no data rows. The error is the first write error
// encountered, if any.
func WriteMonthlyTSV(w io.Writer, records []normalizer.Record, entitlement int) (skipped int, err error) {
	rows, skipped := buildMonthlyRows(records, nil)
	ew := &errWriter{w: w}
	ew.printf("date\tentitlement\tcumulative_total\n")
	for _, row := range rows {
		ew.printf("%s\t%d\t%d\n", row.month.Format("2006-01-02"), entitlement, row.nonPKI)
	}
	return skipped, ew.err
}

// WriteMonthlyTSVPartitioned writes a four-column tab-separated file with a
// header row:
//
//	YYYY-MM-DD  <entitlement>  <non-PKI cumulative total>  <PKI cumulative total>
//
// It behaves like WriteMonthlyTSV but splits each month's count into PKI and
// non-PKI columns using normalizer.IsPKIClient, each tracked as its own
// running cumulative total. Records with a zero TokenCreationTime are
// skipped and counted in the returned value. The header row is always
// written, even when there are no data rows. The error is the first write
// error encountered, if any.
func WriteMonthlyTSVPartitioned(w io.Writer, records []normalizer.Record, entitlement int) (skipped int, err error) {
	rows, skipped := buildMonthlyRows(records, normalizer.IsPKIClient)
	ew := &errWriter{w: w}
	ew.printf("date\tentitlement\tnon_pki_cumulative_total\tpki_cumulative_total\n")
	for _, row := range rows {
		ew.printf("%s\t%d\t%d\t%d\n", row.month.Format("2006-01-02"), entitlement, row.nonPKI, row.pki)
	}
	return skipped, ew.err
}

// WriteMonthlyTSVSoko writes a three-column tab-separated file with no header
// row:
//
//	YYYY-MM-DD  <entitlement>  <total clients>
//
// The date is the last day of the month (not the first, as in WriteMonthlyTSV
// and WriteMonthlyTSVPartitioned). The total is a running cumulative count,
// and months with no records repeat the previous total. If countPKI is true,
// PKI clients (normalizer.IsPKIClient) are tracked separately from non-PKI
// clients and folded into the total as non-PKI + round(PKI / 40); if false,
// all records count toward the total directly, as in WriteMonthlyTSV. Records
// with a zero TokenCreationTime are skipped and counted in the returned
// value. The error is the first write error encountered, if any.
func WriteMonthlyTSVSoko(w io.Writer, records []normalizer.Record, entitlement int, countPKI bool) (skipped int, err error) {
	var isPKI func(normalizer.Record) bool
	if countPKI {
		isPKI = normalizer.IsPKIClient
	}
	rows, skipped := buildMonthlyRows(records, isPKI)
	ew := &errWriter{w: w}
	for _, row := range rows {
		total := row.nonPKI
		if countPKI {
			total = row.nonPKI + int(math.Round(float64(row.pki)/40))
		}
		date := row.month.AddDate(0, 1, -1).Format("2006-01-02") // last day of the month
		ew.printf("%s\t%d\t%d\n", date, entitlement, total)
	}
	return skipped, ew.err
}
