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
		{ClientType: "entity"},
		{ClientType: "entity"},
		{ClientType: "non-entity"},
		{ClientType: "acme"},
	}
	var buf strings.Builder
	PrintSummary(&buf, records, "")
	out := buf.String()

	if !strings.Contains(out, "Total clients:") {
		t.Errorf("expected 'Total clients:' in summary, got: %s", out)
	}
	if !strings.Contains(out, "entity:") {
		t.Error("expected entity count in summary")
	}
	if !strings.Contains(out, "non-entity:") {
		t.Error("expected non-entity count in summary")
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

func TestPrintPKIReport_WithPKI(t *testing.T) {
	pki := []normalizer.Record{
		{
			ClientID:      "pki-001",
			NamespacePath: "[root]",
			ClientType:    "entity",
			AuthMethod:    "cert",
			MountPath:     "auth/cert/",
		},
		{
			ClientID:      "pki-002",
			NamespacePath: "finance/",
			ClientType:    "entity",
			AuthMethod:    "cert",
			MountPath:     "auth/cert/",
		},
	}
	var buf strings.Builder
	PrintPKIReport(&buf, pki)
	out := buf.String()

	if !strings.Contains(out, "PKI (cert) Clients") {
		t.Error("expected PKI section header")
	}
	if !strings.Contains(out, "pki-001") {
		t.Error("expected pki-001 in PKI table")
	}
	if !strings.Contains(out, "PKI Client Summary") {
		t.Error("expected PKI Client Summary section")
	}
	if !strings.Contains(out, "Total clients:") {
		t.Error("expected total count in PKI summary")
	}
}

func TestPrintPKIReport_Empty(t *testing.T) {
	var buf strings.Builder
	PrintPKIReport(&buf, nil)
	out := buf.String()
	if !strings.Contains(out, "no PKI clients found") {
		t.Errorf("expected 'no PKI clients found' message, got: %s", out)
	}
}

func TestShortPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/home/user/exports/jan.csv", "jan.csv"},
		{"jan.csv", "jan.csv"},
		{`C:\Users\exports\jan.csv`, "jan.csv"},
		{"", ""},
	}
	for _, c := range cases {
		got := shortPath(c.in)
		if got != c.want {
			t.Errorf("shortPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
