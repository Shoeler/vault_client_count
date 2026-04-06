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
		{"certificate", "certificate"}, // passthrough — not an acme alias
		{"cert", "cert"},               // passthrough — not an acme alias
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

func TestDeduplicate_PrefersNonEmptyMount(t *testing.T) {
	records := []Record{
		{ClientID: "abc", MountPath: ""},
		{ClientID: "abc", MountPath: "auth/ldap/"},
		{ClientID: "xyz", MountPath: "auth/approle/"},
		{ClientID: "xyz", MountPath: ""},
	}
	out := Deduplicate(records)
	if len(out) != 2 {
		t.Fatalf("expected 2 records after dedup, got %d", len(out))
	}
	for _, r := range out {
		if r.MountPath == "" {
			t.Errorf("client %q kept empty-mount record when a non-empty mount was available", r.ClientID)
		}
	}
}

func TestDeduplicate_KeepsFirstWhenBothEmpty(t *testing.T) {
	records := []Record{
		{ClientID: "abc", MountPath: "", AuthMethod: "first"},
		{ClientID: "abc", MountPath: "", AuthMethod: "second"},
	}
	out := Deduplicate(records)
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d", len(out))
	}
	if out[0].AuthMethod != "first" {
		t.Errorf("expected first occurrence to be kept, got AuthMethod=%q", out[0].AuthMethod)
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
		clientType    string
		mountAccessor string
		want          bool
	}{
		// ACME clients detected by client_type
		{"acme", "", true},
		{"acme", "pki_abc123", true},
		// Cert auth clients detected by mount_accessor prefix
		{"entity", "auth_cert_internal", true},
		{"non-entity", "auth_cert_prod", true},
		{"entity", "AUTH_CERT_xyz", true},
		// Non-PKI clients
		{"entity", "auth_approle_abc", false},
		{"non-entity", "auth_ldap_xyz", false},
		{"secret-sync", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		r := Record{ClientType: c.clientType, MountAccessor: c.mountAccessor}
		got := IsPKIClient(r)
		if got != c.want {
			t.Errorf("IsPKIClient(ClientType=%q, MountAccessor=%q) = %v, want %v",
				c.clientType, c.mountAccessor, got, c.want)
		}
	}
}

func TestPartitionPKI(t *testing.T) {
	// Mix of acme clients (PKI engine), cert auth clients (auth_cert accessor),
	// and regular entity/non-entity clients.
	records := []Record{
		{ClientID: "e1", ClientType: "entity", MountAccessor: "auth_approle_web"},
		{ClientID: "p1", ClientType: "acme", MountAccessor: "pki_abc123"},
		{ClientID: "e2", ClientType: "non-entity", MountAccessor: "auth_ldap_corp"},
		{ClientID: "p2", ClientType: "entity", MountAccessor: "auth_cert_internal"},
		{ClientID: "e3", ClientType: "entity", MountAccessor: "auth_oidc_okta"},
	}

	pki, nonPKI := PartitionPKI(records, IsPKIClient)

	if len(pki) != 2 {
		t.Errorf("expected 2 PKI records, got %d", len(pki))
	}
	if len(nonPKI) != 3 {
		t.Errorf("expected 3 non-PKI records, got %d", len(nonPKI))
	}

	pkiIDs := map[string]bool{"p1": true, "p2": true}
	for _, r := range pki {
		if !pkiIDs[r.ClientID] {
			t.Errorf("unexpected client in PKI partition: %s", r.ClientID)
		}
	}
	nonPKIIDs := map[string]bool{"e1": true, "e2": true, "e3": true}
	for _, r := range nonPKI {
		if !nonPKIIDs[r.ClientID] {
			t.Errorf("unexpected client in non-PKI partition: %s", r.ClientID)
		}
	}
}

// Regression test: cert auth clients (client_type=entity/non-entity with an
// auth_cert mount_accessor) must not be lumped into the non-PKI partition.
// This broke when IsPKIClient was changed to only check client_type=acme.
func TestPartitionPKI_CertAuthClientsArePKI(t *testing.T) {
	records := []Record{
		{ClientID: "cert-entity", ClientType: "entity", MountAccessor: "auth_cert_internal"},
		{ClientID: "cert-nonentity", ClientType: "non-entity", MountAccessor: "auth_cert_prod"},
		{ClientID: "regular", ClientType: "entity", MountAccessor: "auth_approle_web"},
	}

	pki, nonPKI := PartitionPKI(records, IsPKIClient)

	if len(pki) != 2 {
		t.Errorf("expected 2 PKI records (cert auth clients), got %d — cert auth clients are being incorrectly lumped into non-PKI", len(pki))
	}
	if len(nonPKI) != 1 {
		t.Errorf("expected 1 non-PKI record, got %d", len(nonPKI))
	}
	for _, r := range pki {
		if r.ClientID == "regular" {
			t.Error("non-cert client ended up in PKI partition")
		}
	}
}

func TestPartitionPKI_AllPKI(t *testing.T) {
	records := []Record{
		{ClientID: "p1", ClientType: "acme"},
		{ClientID: "p2", ClientType: "acme"},
	}
	pki, nonPKI := PartitionPKI(records, IsPKIClient)
	if len(pki) != 2 {
		t.Errorf("expected 2 PKI, got %d", len(pki))
	}
	if len(nonPKI) != 0 {
		t.Errorf("expected 0 non-PKI, got %d", len(nonPKI))
	}
}

func TestPartitionPKI_NoPKI(t *testing.T) {
	records := []Record{
		{ClientID: "e1", ClientType: "entity"},
		{ClientID: "e2", ClientType: "non-entity"},
	}
	pki, nonPKI := PartitionPKI(records, IsPKIClient)
	if len(pki) != 0 {
		t.Errorf("expected 0 PKI, got %d", len(pki))
	}
	if len(nonPKI) != 2 {
		t.Errorf("expected 2 non-PKI, got %d", len(nonPKI))
	}
}


func TestPartitionPKI_Empty(t *testing.T) {
	pki, nonPKI := PartitionPKI(nil, IsPKIClient)
	if pki != nil || nonPKI != nil {
		t.Error("expected nil slices for empty input")
	}
}
