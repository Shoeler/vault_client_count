package renderer

import (
	"strings"
	"testing"
	"time"

	"github.com/vault-csv-normalizer/internal/normalizer"
)

func mustMonth(ym string) time.Time {
	t, err := time.Parse("2006-01", ym)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

func TestWriteMonthlyTSV_HeaderAndRows(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-01")},
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-01")},
		{ClientType: "non-entity", TokenCreationTime: mustMonth("2024-01")},
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-02")},
		{ClientType: "acme", TokenCreationTime: mustMonth("2024-02")},
	}

	var buf strings.Builder
	WriteMonthlyTSV(&buf, records, 500)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	// Header row + 2 data rows.
	if len(lines) != 3 {
		t.Fatalf("expected 1 header row + 2 data rows, got %d:\n%s", len(lines), buf.String())
	}
	if lines[0] != "date\tentitlement\tcumulative_total" {
		t.Errorf("expected header row, got %q", lines[0])
	}

	// January row: date, entitlement, cumulative total=3.
	jan := strings.Split(lines[1], "\t")
	if len(jan) != 3 {
		t.Fatalf("expected 3 columns in January row, got %d: %q", len(jan), lines[1])
	}
	if jan[0] != "2024-01-01" {
		t.Errorf("expected date '2024-01-01', got %q", jan[0])
	}
	if jan[1] != "500" {
		t.Errorf("expected entitlement '500', got %q", jan[1])
	}
	if jan[2] != "3" {
		t.Errorf("expected cumulative total '3' for January, got %q", jan[2])
	}

	// February row: cumulative total = 3+2 = 5.
	feb := strings.Split(lines[2], "\t")
	if feb[0] != "2024-02-01" {
		t.Errorf("expected date '2024-02-01', got %q", feb[0])
	}
	if feb[2] != "5" {
		t.Errorf("expected cumulative total '5' for February, got %q", feb[2])
	}
}

func TestWriteMonthlyTSV_RowsSortedChronologically(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-03")},
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-01")},
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-02")},
	}

	var buf strings.Builder
	WriteMonthlyTSV(&buf, records, 100)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	if len(lines) != 4 {
		t.Fatalf("expected 1 header row + 3 data rows, got %d", len(lines))
	}
	dates := []string{
		strings.SplitN(lines[1], "\t", 2)[0],
		strings.SplitN(lines[2], "\t", 2)[0],
		strings.SplitN(lines[3], "\t", 2)[0],
	}
	if dates[0] != "2024-01-01" || dates[1] != "2024-02-01" || dates[2] != "2024-03-01" {
		t.Errorf("expected chronological order, got: %v", dates)
	}
}

func TestWriteMonthlyTSV_UnknownTimeBucket(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-01")},
		{ClientType: "non-entity"}, // zero time — skipped
	}

	var buf strings.Builder
	WriteMonthlyTSV(&buf, records, 0)
	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	// Zero-time record is skipped; header row + one dated row.
	if len(lines) != 2 {
		t.Errorf("expected 1 header row + 1 data row (zero-time record skipped), got %d:\n%s", len(lines), out)
	}
	if strings.Contains(out, "(unknown)") {
		t.Errorf("expected no '(unknown)' row for zero-time records, got:\n%s", out)
	}
}

func TestWriteMonthlyTSV_EntitlementColumn(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-01")},
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-02")},
	}

	var buf strings.Builder
	WriteMonthlyTSV(&buf, records, 1234)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	// lines[0] is the header row; only data rows carry the entitlement column.
	for i, line := range lines[1:] {
		cols := strings.Split(line, "\t")
		if len(cols) != 3 {
			t.Fatalf("row %d: expected 3 columns, got %d: %q", i, len(cols), line)
		}
		if cols[1] != "1234" {
			t.Errorf("row %d: expected entitlement '1234', got %q", i, cols[1])
		}
	}
}

func TestWriteMonthlyTSV_CountsAccurate(t *testing.T) {
	jan := mustMonth("2024-01")
	feb := mustMonth("2024-02")
	records := []normalizer.Record{
		{ClientType: "entity", TokenCreationTime: jan},
		{ClientType: "entity", TokenCreationTime: jan},
		{ClientType: "entity", TokenCreationTime: jan},
		{ClientType: "non-entity", TokenCreationTime: jan},
		{ClientType: "acme", TokenCreationTime: feb},
	}

	var buf strings.Builder
	WriteMonthlyTSV(&buf, records, 500)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	if len(lines) != 3 {
		t.Fatalf("expected 1 header row + 2 data rows, got %d", len(lines))
	}

	janCols := strings.Split(lines[1], "\t")
	if janCols[2] != "4" {
		t.Errorf("expected January cumulative total=4, got %q", janCols[2])
	}

	febCols := strings.Split(lines[2], "\t")
	if febCols[2] != "5" {
		t.Errorf("expected February cumulative total=5 (4+1), got %q", febCols[2])
	}
}

func TestWriteMonthlyTSV_EmptyInput(t *testing.T) {
	var buf strings.Builder
	WriteMonthlyTSV(&buf, nil, 500)
	got := strings.TrimRight(buf.String(), "\n")
	if got != "date\tentitlement\tcumulative_total" {
		t.Errorf("expected header-only output for empty input, got: %q", buf.String())
	}
}

func TestWriteMonthlyTSVPartitioned_SplitsPKIAndNonPKI(t *testing.T) {
	jan := mustMonth("2024-01")
	feb := mustMonth("2024-02")
	records := []normalizer.Record{
		{ClientType: "entity", TokenCreationTime: jan},
		{ClientType: "entity", TokenCreationTime: jan},
		{ClientType: "acme", TokenCreationTime: jan},
		{ClientType: "entity", TokenCreationTime: feb},
		{ClientType: "acme", TokenCreationTime: feb},
		{MountAccessor: "auth_cert_1234", TokenCreationTime: feb},
	}

	var buf strings.Builder
	WriteMonthlyTSVPartitioned(&buf, records, 500)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	if len(lines) != 3 {
		t.Fatalf("expected 1 header row + 2 data rows, got %d:\n%s", len(lines), buf.String())
	}
	if lines[0] != "date\tentitlement\tnon_pki_cumulative_total\tpki_cumulative_total" {
		t.Errorf("expected header row, got %q", lines[0])
	}

	janCols := strings.Split(lines[1], "\t")
	if len(janCols) != 4 {
		t.Fatalf("expected 4 columns in January row, got %d: %q", len(janCols), lines[1])
	}
	if janCols[0] != "2024-01-01" {
		t.Errorf("expected date '2024-01-01', got %q", janCols[0])
	}
	if janCols[1] != "500" {
		t.Errorf("expected entitlement '500', got %q", janCols[1])
	}
	if janCols[2] != "2" {
		t.Errorf("expected January non-PKI cumulative '2', got %q", janCols[2])
	}
	if janCols[3] != "1" {
		t.Errorf("expected January PKI cumulative '1', got %q", janCols[3])
	}

	febCols := strings.Split(lines[2], "\t")
	if febCols[2] != "3" {
		t.Errorf("expected February non-PKI cumulative '3' (2+1), got %q", febCols[2])
	}
	if febCols[3] != "3" {
		t.Errorf("expected February PKI cumulative '3' (1+2), got %q", febCols[3])
	}
}

func TestWriteMonthlyTSVPartitioned_MonthWithOnlyPKI(t *testing.T) {
	jan := mustMonth("2024-01")
	feb := mustMonth("2024-02")
	records := []normalizer.Record{
		{ClientType: "entity", TokenCreationTime: jan},
		{ClientType: "acme", TokenCreationTime: feb},
	}

	var buf strings.Builder
	WriteMonthlyTSVPartitioned(&buf, records, 0)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 1 header row + 2 data rows, got %d:\n%s", len(lines), buf.String())
	}

	febCols := strings.Split(lines[2], "\t")
	if febCols[2] != "1" {
		t.Errorf("expected February non-PKI cumulative to carry forward as '1', got %q", febCols[2])
	}
	if febCols[3] != "1" {
		t.Errorf("expected February PKI cumulative '1', got %q", febCols[3])
	}
}

func TestWriteMonthlyTSVPartitioned_EmptyInput(t *testing.T) {
	var buf strings.Builder
	WriteMonthlyTSVPartitioned(&buf, nil, 500)
	got := strings.TrimRight(buf.String(), "\n")
	if got != "date\tentitlement\tnon_pki_cumulative_total\tpki_cumulative_total" {
		t.Errorf("expected header-only output for empty input, got: %q", buf.String())
	}
}

func TestWriteMonthlyTSVSoko_NoHeaderThreeColumnsEndOfMonth(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-01")},
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-01")},
		{ClientType: "non-entity", TokenCreationTime: mustMonth("2024-01")},
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-02")},
		{ClientType: "acme", TokenCreationTime: mustMonth("2024-02")},
	}

	var buf strings.Builder
	WriteMonthlyTSVSoko(&buf, records, 500, false)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")

	// No header — exactly 2 data rows.
	if len(lines) != 2 {
		t.Fatalf("expected 2 data rows (no header), got %d:\n%s", len(lines), buf.String())
	}

	jan := strings.Split(lines[0], "\t")
	if len(jan) != 3 {
		t.Fatalf("expected 3 columns in January row, got %d: %q", len(jan), lines[0])
	}
	if jan[0] != "2024-01-31" {
		t.Errorf("expected end-of-month date '2024-01-31', got %q", jan[0])
	}
	if jan[1] != "500" {
		t.Errorf("expected entitlement '500', got %q", jan[1])
	}
	if jan[2] != "3" {
		t.Errorf("expected total '3' for January, got %q", jan[2])
	}

	// 2024 is a leap year — February has 29 days.
	feb := strings.Split(lines[1], "\t")
	if feb[0] != "2024-02-29" {
		t.Errorf("expected end-of-month date '2024-02-29', got %q", feb[0])
	}
	if feb[2] != "5" {
		t.Errorf("expected total '5' for February (acme counted plainly since -p not set), got %q", feb[2])
	}
}

func TestWriteMonthlyTSVSoko_DecemberRollsToNextYear(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", TokenCreationTime: mustMonth("2024-12")},
	}

	var buf strings.Builder
	WriteMonthlyTSVSoko(&buf, records, 0, false)
	line := strings.TrimRight(buf.String(), "\n")
	cols := strings.Split(line, "\t")
	if cols[0] != "2024-12-31" {
		t.Errorf("expected end-of-month date '2024-12-31', got %q", cols[0])
	}
}

func TestWriteMonthlyTSVSoko_CountPKIDividesBy40AndRounds(t *testing.T) {
	jan := mustMonth("2024-01")
	feb := mustMonth("2024-02")
	records := []normalizer.Record{}
	// January: 2 non-PKI, 20 PKI (acme). 20/40 = 0.5 → rounds to 1. Total = 3.
	for i := 0; i < 2; i++ {
		records = append(records, normalizer.Record{ClientType: "entity", TokenCreationTime: jan})
	}
	for i := 0; i < 20; i++ {
		records = append(records, normalizer.Record{ClientType: "acme", TokenCreationTime: jan})
	}
	// February: +3 non-PKI (cumulative 5), +20 PKI (cumulative 40). 40/40 = 1.0 exact. Total = 6.
	for i := 0; i < 3; i++ {
		records = append(records, normalizer.Record{ClientType: "entity", TokenCreationTime: feb})
	}
	for i := 0; i < 20; i++ {
		records = append(records, normalizer.Record{ClientType: "acme", TokenCreationTime: feb})
	}

	var buf strings.Builder
	WriteMonthlyTSVSoko(&buf, records, 500, true)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 rows, got %d:\n%s", len(lines), buf.String())
	}

	janCols := strings.Split(lines[0], "\t")
	if janCols[2] != "3" {
		t.Errorf("expected January total '3' (2 non-PKI + round(20/40)=1), got %q", janCols[2])
	}

	febCols := strings.Split(lines[1], "\t")
	if febCols[2] != "6" {
		t.Errorf("expected February total '6' (5 non-PKI + round(40/40)=1), got %q", febCols[2])
	}
}

func TestWriteMonthlyTSVSoko_EmptyInput(t *testing.T) {
	var buf strings.Builder
	WriteMonthlyTSVSoko(&buf, nil, 500, true)
	if buf.Len() != 0 {
		t.Errorf("expected no output for empty input, got: %q", buf.String())
	}
}
