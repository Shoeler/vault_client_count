package renderer

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vault-csv-normalizer/internal/normalizer"
)

func TestPrintTable_NoRecords(t *testing.T) {
	var buf strings.Builder
	PrintTable(&buf, nil)
	if !strings.Contains(buf.String(), "no records") {
		t.Errorf("expected 'no records' message, got: %q", buf.String())
	}
}

func TestPrintTable_ZeroTimeFmtDash(t *testing.T) {
	records := []normalizer.Record{
		{
			ClientID:      "no-time",
			NamespacePath: "[root]",
			ClientType:    "entity",
		},
	}
	var buf strings.Builder
	PrintTable(&buf, records)
	if !strings.Contains(buf.String(), "—") {
		t.Error("expected '—' for zero time value")
	}
}

func TestPrintSummary_MountPathsSorted(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", MountPath: "auth/zzz/"},
		{ClientType: "entity", MountPath: "auth/aaa/"},
		{ClientType: "entity", MountPath: "auth/mmm/"},
	}
	var buf strings.Builder
	PrintSummary(&buf, records, "")
	out := buf.String()

	posAAA := strings.Index(out, "auth/aaa/")
	posMMM := strings.Index(out, "auth/mmm/")
	posZZZ := strings.Index(out, "auth/zzz/")
	if posAAA < 0 || posMMM < 0 || posZZZ < 0 {
		t.Fatalf("one or more mount paths missing from output:\n%s", out)
	}
	if !(posAAA < posMMM && posMMM < posZZZ) {
		t.Errorf("mount paths not in alphabetical order in output:\n%s", out)
	}
}

func TestPrintSummary_NoMountPath(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", MountPath: ""},
	}
	var buf strings.Builder
	PrintSummary(&buf, records, "")
	out := buf.String()
	if !strings.Contains(out, "(no mount)") {
		t.Errorf("expected '(no mount)' placeholder for empty mount path, got:\n%s", out)
	}
}

func TestPrintSummary_CustomLabel(t *testing.T) {
	records := []normalizer.Record{{ClientType: "entity"}}
	var buf strings.Builder
	PrintSummary(&buf, records, "Non-PKI Client Summary")
	out := buf.String()
	if !strings.Contains(out, "Non-PKI Client Summary") {
		t.Errorf("expected custom label in output, got: %s", out)
	}
}

// TestPrintTable_AliasColumnAppearsWhenPresent verifies that the Entity Alias
// column is added automatically when at least one record has a non-empty
// EntityAliasName, and that the original full alias value (not the stripped
// base) is shown.
func TestPrintTable_AliasColumnAppearsWhenPresent(t *testing.T) {
	records := []normalizer.Record{
		{ClientID: "a", ClientType: "entity", EntityAliasName: "alice-001"},
		{ClientID: "b", ClientType: "entity", EntityAliasName: "alice-002"},
	}
	var buf strings.Builder
	PrintTable(&buf, records)
	out := buf.String()

	if !strings.Contains(out, "Entity Alias") {
		t.Error("expected 'Entity Alias' column header when records have aliases")
	}
	if !strings.Contains(out, "alice-001") {
		t.Error("expected original alias 'alice-001' in output, not the stripped base")
	}
	if !strings.Contains(out, "alice-002") {
		t.Error("expected original alias 'alice-002' in output")
	}
}

func TestPrintTable_AliasColumnHiddenWhenAbsent(t *testing.T) {
	records := []normalizer.Record{
		{ClientID: "a", ClientType: "entity"},
		{ClientID: "b", ClientType: "non-entity"},
	}
	var buf strings.Builder
	PrintTable(&buf, records)
	out := buf.String()

	if strings.Contains(out, "Entity Alias") {
		t.Error("expected no 'Entity Alias' column when no records have aliases")
	}
}

// ==== P-R1 (replaces TestPrintTable_RendersRows) ====
func TestPrintTable_RendersRows(t *testing.T) {
	records := []normalizer.Record{
		{
			Source:            "/exports/2024/jan.csv",
			ClientID:          "abc-123",
			NamespacePath:     "[root]",
			ClientType:        "entity",
			MountAccessor:     "auth_approle_1",
			MountPath:         "auth/approle/",
			TokenCreationTime: time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		},
		{
			Source:            "feb.csv",
			ClientID:          "def-456",
			NamespacePath:     "education/",
			ClientType:        "non-entity",
			MountAccessor:     "auth_ldap_2",
			MountPath:         "auth/ldap/",
			TokenCreationTime: time.Date(2024, 2, 1, 8, 0, 0, 0, time.UTC),
		},
	}
	var buf strings.Builder
	PrintTable(&buf, records)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("expected header, separator and 2 rows, got %d lines:\n%s", len(lines), buf.String())
	}

	// Cells are separated by two or more spaces; no cell here contains two spaces.
	cells := func(line string) []string { return regexp.MustCompile(` {2,}`).Split(line, -1) }
	header := []string{"Namespace Path", "Mount Path", "Mount Accessor", "Token Created", "Client ID", "Source File"}
	rows := [][]string{
		{"[root]", "auth/approle/", "auth_approle_1", "2024-01-15 10:00:00Z", "abc-123", "jan.csv"},
		{"education/", "auth/ldap/", "auth_ldap_2", "2024-02-01 08:00:00Z", "def-456", "feb.csv"},
	}
	if got := cells(lines[0]); strings.Join(got, "|") != strings.Join(header, "|") {
		t.Errorf("header cells = %q, want %q", got, header)
	}
	for i, want := range rows {
		line := lines[2+i]
		if got := cells(line); strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("row %d cells = %q, want %q", i, got, want)
		}
		// Each cell starts in the same column as its header.
		for j, cell := range want {
			if hc, rc := strings.Index(lines[0], header[j]), strings.Index(line, cell); hc != rc {
				t.Errorf("row %d: %q starts at column %d, header %q at %d", i, cell, rc, header[j], hc)
			}
		}
	}
}

// ==== P-R2 (replaces TestPrintTable_EmptySourceRendersAsDot) ====
// filepath.Base("") is ".", so a record with no Source shows "." in the Source
// File column. Pinned so any change is deliberate.
func TestPrintTable_EmptySourceRendersAsDot(t *testing.T) {
	records := []normalizer.Record{
		{ClientID: "abc", ClientType: "entity", Source: ""},
	}
	var buf strings.Builder
	PrintTable(&buf, records)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	fields := strings.Fields(lines[len(lines)-1])
	if got := fields[len(fields)-1]; got != "." {
		t.Errorf("Source File cell = %q, want \".\"; output:\n%s", got, buf.String())
	}
}

// ==== P-R3 (new) ====
func TestPrintTable_OIDCUsernameColumn(t *testing.T) {
	records := []normalizer.Record{
		{ClientID: "a", EntityAliasName: "uuid-1234", EntityAliasMetadataUsername: "alice"},
		{ClientID: "b"},
	}
	var buf strings.Builder
	PrintTable(&buf, records)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	last2 := func(line string) string {
		c := regexp.MustCompile(` {2,}`).Split(strings.TrimSpace(line), -1)
		return strings.Join(c[len(c)-2:], "|")
	}
	if got := last2(lines[0]); got != "Entity Alias|OIDC Username" {
		t.Errorf("last two headers = %q, want Entity Alias|OIDC Username", got)
	}
	if got := last2(lines[2]); got != "uuid-1234|alice" {
		t.Errorf("last two cells of row a = %q, want uuid-1234|alice", got)
	}

	buf.Reset()
	PrintTable(&buf, []normalizer.Record{{ClientID: "c", EntityAliasName: "bob"}})
	if strings.Contains(buf.String(), "OIDC Username") {
		t.Error("OIDC Username column must be omitted when no record has a metadata username")
	}
}

// summaryLines returns the non-blank lines of out with runs of whitespace
// collapsed to one space, so assertions pin content and order, not padding.
func summaryLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			lines = append(lines, strings.Join(f, " "))
		}
	}
	return lines
}

// ==== P-R4 (replaces TestPrintSummary and TestPrintSummary_MultipleTypesPerMount) ====
func TestPrintSummary(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", MountPath: "auth/approle/"},
		{ClientType: "entity", MountPath: "auth/approle/"},
		{ClientType: "non-entity", MountPath: "auth/ldap/"}, // listed before entity, printed after it
		{ClientType: "entity", MountPath: "auth/ldap/"},
		{ClientType: "entity", MountPath: "auth/ldap/"},
		{ClientType: "acme", MountPath: "pki/"},
	}
	var buf strings.Builder
	PrintSummary(&buf, records, "")
	want := []string{
		"Summary",
		"-------",
		"Mount Path Client Type Count",
		"------------- ----------- -----",
		"auth/approle/ entity 2",
		"subtotal: 2",
		"auth/ldap/ entity 2",
		"non-entity 1",
		"subtotal: 3",
		"pki/ acme 1",
		"subtotal: 1",
		"------------- ----------- -----",
		"TOTAL: 6",
	}
	got := summaryLines(buf.String())
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("summary mismatch\ngot:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// ==== P-R5 (new) ====
func TestPrintSummary_UnlistedTypesSortedAfterKnownTypes(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "zeta-type", MountPath: "auth/x/"},
		{ClientType: "alpha-type", MountPath: "auth/x/"},
		{ClientType: "unknown", MountPath: "auth/x/"},
		{ClientType: "entity", MountPath: "auth/x/"},
	}
	var buf strings.Builder
	PrintSummary(&buf, records, "S")
	got := summaryLines(buf.String())
	want := []string{"auth/x/ entity 1", "unknown 1", "alpha-type 1", "zeta-type 1", "subtotal: 4"}
	if strings.Join(got[4:9], "\n") != strings.Join(want, "\n") {
		t.Errorf("type rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// ==== P-R6 (new) ====
func TestPrintSummary_EmptyPrintsNothing(t *testing.T) {
	// main prints a PKI and a non-PKI summary with -p; an empty partition must
	// not produce a header-only section.
	var buf strings.Builder
	PrintSummary(&buf, nil, "PKI Client Summary")
	if buf.Len() != 0 {
		t.Errorf("expected no output for empty records, got %q", buf.String())
	}
}
