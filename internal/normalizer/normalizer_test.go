package normalizer

import (
	"testing"
	"time"

	"github.com/vault-csv-normalizer/internal/parser"
)

func TestNormalizeNamespacePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "[root]"},
		{"[root]", "[root]"},
		{"root", "[root]"},
		{"education", "education/"},
		{"education/", "education/"},
		{"finance/training", "finance/training/"},
	}
	for _, c := range cases {
		got := normalizeNamespacePath(c.in)
		if got != c.want {
			t.Errorf("normalizeNamespacePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeClientType(t *testing.T) {
	cases := []struct{ in, want string }{
		{"entity", "entity"},
		{"Entity", "entity"},
		{"ENTITY", "entity"},
		{"non-entity", "non-entity"},
		{"non_entity", "non-entity"},
		{"Non-Entity Client", "non-entity"},
		{"acme", "acme"},
		{"certificate", "acme"},
		{"cert", "acme"},
		{"secret-sync", "secret-sync"},
		{"secret_sync", "secret-sync"},
		{"secrets sync", "secret-sync"},
		{"", "unknown"},
		{"some-future-type", "some-future-type"}, // passthrough
	}
	for _, c := range cases {
		got := normalizeClientType(c.in)
		if got != c.want {
			t.Errorf("normalizeClientType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseTime(t *testing.T) {
	cases := []struct {
		in   string
		want time.Time
	}{
		{"2024-01-15T10:00:00Z", time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)},
		{"2024-01-15T10:00:00+00:00", time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)},
		{"2024-01-15", time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)},
		{"", time.Time{}},
		{"N/A", time.Time{}},
		{"0", time.Time{}},
		{"garbage", time.Time{}},
	}
	for _, c := range cases {
		got := parseTime(c.in)
		if !got.Equal(c.want) {
			t.Errorf("parseTime(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	raw := []parser.RawRecord{
		{
			Source:             "jan.csv",
			ClientID:           "abc-123",
			NamespaceID:        "",
			NamespacePath:      "root",
			MountPath:          "auth/approle",
			MountType:          "APPROLE",
			AuthMethod:         "AppRole",
			ClientType:         "non_entity",
			TokenCreationTime:  "2024-01-01T00:00:00Z",
		},
	}
	records := Normalize(raw)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.NamespacePath != "[root]" {
		t.Errorf("NamespacePath: got %q, want [root]", r.NamespacePath)
	}
	if r.NamespaceID != "root" {
		t.Errorf("NamespaceID: got %q, want root", r.NamespaceID)
	}
	if r.MountPath != "auth/approle/" {
		t.Errorf("MountPath: got %q, want auth/approle/", r.MountPath)
	}
	if r.MountType != "approle" {
		t.Errorf("MountType: got %q, want approle", r.MountType)
	}
	if r.AuthMethod != "approle" {
		t.Errorf("AuthMethod: got %q, want approle", r.AuthMethod)
	}
	if r.ClientType != "non-entity" {
		t.Errorf("ClientType: got %q, want non-entity", r.ClientType)
	}
	want := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if !r.TokenCreationTime.Equal(want) {
		t.Errorf("TokenCreationTime: got %v, want %v", r.TokenCreationTime, want)
	}
}

func TestFilterByNamespace(t *testing.T) {
	records := []Record{
		{NamespacePath: "[root]", ClientType: "entity"},
		{NamespacePath: "education/", ClientType: "non-entity"},
		{NamespacePath: "education/training/", ClientType: "entity"},
		{NamespacePath: "finance/", ClientType: "entity"},
	}
	filtered := FilterByNamespace(records, "education")
	if len(filtered) != 2 {
		t.Errorf("expected 2 records, got %d", len(filtered))
	}
}

func TestFilterByClientType(t *testing.T) {
	records := []Record{
		{ClientType: "entity"},
		{ClientType: "non-entity"},
		{ClientType: "entity"},
		{ClientType: "acme"},
	}
	filtered := FilterByClientType(records, "entity")
	if len(filtered) != 2 {
		t.Errorf("expected 2 entity records, got %d", len(filtered))
	}
}

func TestSort(t *testing.T) {
	records := []Record{
		{NamespacePath: "zzz/"},
		{NamespacePath: "[root]"},
		{NamespacePath: "aaa/"},
	}
	if err := Sort(records, "namespace_path"); err != nil {
		t.Fatalf("Sort: %v", err)
	}
	want := []string{"[root]", "aaa/", "zzz/"}
	for i, r := range records {
		if r.NamespacePath != want[i] {
			t.Errorf("records[%d].NamespacePath = %q, want %q", i, r.NamespacePath, want[i])
		}
	}
}

func TestSort_UnknownKey(t *testing.T) {
	if err := Sort(nil, "bogus_column"); err == nil {
		t.Error("expected error for unknown sort key, got nil")
	}
}

func TestIsPKIClient(t *testing.T) {
	cases := []struct {
		authMethod string
		want       bool
	}{
		{"cert", true},
		{"Cert", false},   // already normalized to lowercase before IsPKIClient is called
		{"approle", false},
		{"ldap", false},
		{"", false},
	}
	for _, c := range cases {
		r := Record{AuthMethod: c.authMethod}
		got := IsPKIClient(r)
		if got != c.want {
			t.Errorf("IsPKIClient(AuthMethod=%q) = %v, want %v", c.authMethod, got, c.want)
		}
	}
}

func TestIsPKIClient_NormalizationRoundtrip(t *testing.T) {
	// Simulate a real record going through Normalize, which lowercases AuthMethod.
	raw := []parser.RawRecord{
		{ClientID: "pki-001", AuthMethod: "Cert", ClientType: "entity"},
		{ClientID: "pki-002", AuthMethod: "CERT", ClientType: "entity"},
		{ClientID: "other-001", AuthMethod: "ApprOle", ClientType: "entity"},
	}
	records := Normalize(raw)
	if !IsPKIClient(records[0]) {
		t.Error("expected Cert (mixed case) to be recognized as PKI after normalization")
	}
	if !IsPKIClient(records[1]) {
		t.Error("expected CERT (uppercase) to be recognized as PKI after normalization")
	}
	if IsPKIClient(records[2]) {
		t.Error("expected approle to NOT be recognized as PKI")
	}
}

func TestPartitionPKI(t *testing.T) {
	records := []Record{
		{ClientID: "e1", AuthMethod: "approle", ClientType: "entity"},
		{ClientID: "p1", AuthMethod: "cert", ClientType: "entity"},
		{ClientID: "e2", AuthMethod: "ldap", ClientType: "non-entity"},
		{ClientID: "p2", AuthMethod: "cert", ClientType: "entity"},
		{ClientID: "e3", AuthMethod: "oidc", ClientType: "entity"},
	}

	pki, nonPKI := PartitionPKI(records)

	if len(pki) != 2 {
		t.Errorf("expected 2 PKI records, got %d", len(pki))
	}
	if len(nonPKI) != 3 {
		t.Errorf("expected 3 non-PKI records, got %d", len(nonPKI))
	}
	for _, r := range pki {
		if r.AuthMethod != "cert" {
			t.Errorf("PKI partition contains non-cert record: %s", r.ClientID)
		}
	}
	for _, r := range nonPKI {
		if r.AuthMethod == "cert" {
			t.Errorf("non-PKI partition contains cert record: %s", r.ClientID)
		}
	}
}

func TestPartitionPKI_AllPKI(t *testing.T) {
	records := []Record{
		{ClientID: "p1", AuthMethod: "cert"},
		{ClientID: "p2", AuthMethod: "cert"},
	}
	pki, nonPKI := PartitionPKI(records)
	if len(pki) != 2 {
		t.Errorf("expected 2 PKI, got %d", len(pki))
	}
	if len(nonPKI) != 0 {
		t.Errorf("expected 0 non-PKI, got %d", len(nonPKI))
	}
}

func TestPartitionPKI_NoPKI(t *testing.T) {
	records := []Record{
		{ClientID: "e1", AuthMethod: "approle"},
		{ClientID: "e2", AuthMethod: "ldap"},
	}
	pki, nonPKI := PartitionPKI(records)
	if len(pki) != 0 {
		t.Errorf("expected 0 PKI, got %d", len(pki))
	}
	if len(nonPKI) != 2 {
		t.Errorf("expected 2 non-PKI, got %d", len(nonPKI))
	}
}

func TestPartitionPKI_Empty(t *testing.T) {
	pki, nonPKI := PartitionPKI(nil)
	if pki != nil || nonPKI != nil {
		t.Error("expected nil slices for empty input")
	}
}
