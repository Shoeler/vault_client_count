package renderer

import (
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

func TestPrintTable_RendersRows(t *testing.T) {
	records := []normalizer.Record{
		{
			Source:             "jan.csv",
			ClientID:           "abc-123",
			NamespacePath:      "[root]",
			ClientType:         "entity",
			AuthMethod:         "approle",
			MountPath:          "auth/approle/",
			TokenCreationTime:  time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		},
		{
			Source:             "feb.csv",
			ClientID:           "def-456",
			NamespacePath:      "education/",
			ClientType:         "non-entity",
			AuthMethod:         "ldap",
			MountPath:          "auth/ldap/",
			TokenCreationTime:  time.Date(2024, 2, 1, 8, 0, 0, 0, time.UTC),
		},
	}

	var buf strings.Builder
	PrintTable(&buf, records)
	out := buf.String()

	// Headers present
	if !strings.Contains(out, "Namespace Path") {
		t.Error("expected header 'Namespace Path'")
	}
	if !strings.Contains(out, "Client Type") {
		t.Error("expected header 'Client Type'")
	}

	// Data rows present
	if !strings.Contains(out, "abc-123") {
		t.Error("expected client_id 'abc-123'")
	}
	if !strings.Contains(out, "education/") {
		t.Error("expected namespace 'education/'")
	}
	if !strings.Contains(out, "non-entity") {
		t.Error("expected client type 'non-entity'")
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

func TestPrintSummary(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", MountPath: "auth/approle/"},
		{ClientType: "entity", MountPath: "auth/approle/"},
		{ClientType: "non-entity", MountPath: "auth/ldap/"},
		{ClientType: "acme", MountPath: "pki/"},
	}
	var buf strings.Builder
	PrintSummary(&buf, records, "")
	out := buf.String()

	if !strings.Contains(out, "Mount Path") {
		t.Errorf("expected 'Mount Path' column header, got:\n%s", out)
	}
	if !strings.Contains(out, "Client Type") {
		t.Errorf("expected 'Client Type' column header, got:\n%s", out)
	}
	if !strings.Contains(out, "auth/approle/") {
		t.Errorf("expected mount path 'auth/approle/' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "auth/ldap/") {
		t.Errorf("expected mount path 'auth/ldap/' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "pki/") {
		t.Errorf("expected mount path 'pki/' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "entity") {
		t.Errorf("expected client type 'entity' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "TOTAL:") {
		t.Errorf("expected 'TOTAL:' grand total line, got:\n%s", out)
	}
	if !strings.Contains(out, "subtotal:") {
		t.Errorf("expected 'subtotal:' per-mount line, got:\n%s", out)
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

func TestPrintSummary_MultipleTypesPerMount(t *testing.T) {
	records := []normalizer.Record{
		{ClientType: "entity", MountPath: "auth/ldap/"},
		{ClientType: "non-entity", MountPath: "auth/ldap/"},
		{ClientType: "entity", MountPath: "auth/ldap/"},
	}
	var buf strings.Builder
	PrintSummary(&buf, records, "")
	out := buf.String()

	// auth/ldap/ should appear once as the mount label, with both types listed.
	if count := strings.Count(out, "auth/ldap/"); count != 1 {
		t.Errorf("expected mount path to appear exactly once (as label), got %d occurrences:\n%s", count, out)
	}
	if !strings.Contains(out, "entity") {
		t.Error("expected 'entity' in output")
	}
	if !strings.Contains(out, "non-entity") {
		t.Error("expected 'non-entity' in output")
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

// TestPrintTable_EmptySourceRendersAsDot pins the behaviour of filepath.Base(""),
// which returns "." rather than "". Records with no Source will show "." in the
// Source File column. This differs from the old shortPath("") == "" behaviour
// and is documented here so any future change is a deliberate decision.
func TestPrintTable_EmptySourceRendersAsDot(t *testing.T) {
	records := []normalizer.Record{
		{ClientID: "abc", ClientType: "entity", Source: ""},
	}
	var buf strings.Builder
	PrintTable(&buf, records)
	out := buf.String()
	if !strings.Contains(out, ".") {
		t.Errorf("expected '.' for empty Source (filepath.Base(\"\") = \".\"), got:\n%s", out)
	}
}

