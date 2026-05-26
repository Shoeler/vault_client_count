package normalizer

import (
	"strings"
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
		got := ParseTime(c.in)
		if !got.Equal(c.want) {
			t.Errorf("ParseTime(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	raw := []parser.RawRecord{
		{
			Source:            "jan.csv",
			ClientID:          "abc-123",
			EntityName:        "  Alice Smith  ",
			NamespaceID:       "",
			NamespacePath:     "root",
			MountPath:         "auth/approle",
			MountType:         "APPROLE",
			AuthMethod:        "AppRole",
			ClientType:        "non_entity",
			TokenCreationTime: "2024-01-01T00:00:00Z",
		},
	}
	records := Normalize(raw)
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.EntityName != "Alice Smith" {
		t.Errorf("EntityName: got %q, want Alice Smith", r.EntityName)
	}
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

func TestFilterAbandonedClients(t *testing.T) {
	records := []Record{
		// removed as merged/deleted: mount path present
		{ClientID: "drop-merged-1", EntityName: "", EntityAliasName: "", MountPath: "auth/ldap/", MountType: "ldap"},
		// removed as merged/deleted: mount path present even if mount type is blank
		{ClientID: "drop-merged-2", EntityName: "", EntityAliasName: "", MountPath: "auth/oidc/", MountType: ""},
		// removed as no mount: mount path missing
		{ClientID: "drop-nomount-1", EntityName: "", EntityAliasName: "", MountPath: "", MountType: "ldap"},
		// removed as merged/deleted PKI (auth_cert accessor, mount present)
		{ClientID: "drop-merged-pki-1", EntityName: "", EntityAliasName: "", MountPath: "auth/cert/", MountType: "cert", MountAccessor: "auth_cert_abc123"},
		// removed as no-mount PKI (auth_cert accessor, mount missing)
		{ClientID: "drop-nomount-pki-1", EntityName: "", EntityAliasName: "", MountPath: "", MountType: "cert", MountAccessor: "auth_cert_xyz789"},
		// keep: entity name present
		{ClientID: "keep-3", EntityName: "Alice", EntityAliasName: "", MountPath: "auth/ldap/", MountType: "ldap"},
		// keep: entity alias present
		{ClientID: "keep-4", EntityName: "", EntityAliasName: "alice", MountPath: "auth/ldap/", MountType: "ldap"},
	}

	out, counts := FilterAbandonedClients(records)
	if counts.NoMount != 2 {
		t.Fatalf("expected NoMount=2, got %d", counts.NoMount)
	}
	if counts.NoMountPKI != 1 {
		t.Fatalf("expected NoMountPKI=1, got %d", counts.NoMountPKI)
	}
	if counts.MergedDeleted != 3 {
		t.Fatalf("expected MergedDeleted=3, got %d", counts.MergedDeleted)
	}
	if counts.MergedDeletedPKI != 1 {
		t.Fatalf("expected MergedDeletedPKI=1, got %d", counts.MergedDeletedPKI)
	}
	if counts.Total() != 5 {
		t.Fatalf("expected Total=5, got %d", counts.Total())
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 records after filter, got %d", len(out))
	}
	for _, r := range out {
		if strings.HasPrefix(r.ClientID, "drop-") {
			t.Fatal("drop-* records should have been removed")
		}
	}
}

func TestFilterSince(t *testing.T) {
	records := []Record{
		{ClientID: "old", TokenCreationTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		{ClientID: "boundary", TokenCreationTime: time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)},
		{ClientID: "new", TokenCreationTime: time.Date(2024, 12, 1, 0, 0, 0, 0, time.UTC)},
		{ClientID: "unknown", TokenCreationTime: time.Time{}}, // zero — always kept
	}
	since := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	out := FilterSince(records, since)

	ids := make(map[string]bool, len(out))
	for _, r := range out {
		ids[r.ClientID] = true
	}
	if ids["old"] {
		t.Error("expected 'old' to be filtered out")
	}
	if !ids["boundary"] {
		t.Error("expected 'boundary' (exactly at since) to be kept")
	}
	if !ids["new"] {
		t.Error("expected 'new' to be kept")
	}
	if !ids["unknown"] {
		t.Error("expected 'unknown' (zero time) to be kept")
	}
}

func TestParseTime_Formats(t *testing.T) {
	cases := []struct {
		in   string
		want time.Time
	}{
		{"2024-06-15", time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)},
		{"2024-06-15T10:30:00Z", time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)},
		{"06/15/2024", time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)},
		{"", time.Time{}},
		{"N/A", time.Time{}},
		{"not-a-date", time.Time{}},
	}
	for _, c := range cases {
		got := ParseTime(c.in)
		if !got.Equal(c.want) {
			t.Errorf("ParseTime(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestBaseAlias(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice@corp.com", "alice"},
		{"sbishop@hashicorp.com", "sbishop"},
		{"abc@234", "abc"},
		{"sbishop-t0", "sbishop-t0"}, // BaseAlias alone does not strip tier
		{"plain", "plain"},
		{"", ""},
		{"@leading", ""},
	}
	for _, c := range cases {
		got := BaseAlias(c.in)
		if got != c.want {
			t.Errorf("BaseAlias(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestStripTierSuffix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice-t0", "alice"},
		{"alice-t1", "alice"},
		{"alice-t2", "alice"},
		{"alice-t3", "alice-t3"}, // only t0–t2 are stripped
		{"alice-t10", "alice-t10"},
		{"alice-T0", "alice-T0"}, // case-sensitive
		{"alice", "alice"},
		{"-t0", ""},  // degenerate: only the suffix
		{"t0", "t0"}, // no hyphen
		{"", ""},
	}
	for _, c := range cases {
		got := StripTierSuffix(c.in)
		if got != c.want {
			t.Errorf("StripTierSuffix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestStripTierSuffix_AfterBaseAlias(t *testing.T) {
	// Strip domain then tier suffix.
	cases := []struct{ in, want string }{
		{"alice-t0@corp.com", "alice"},
		{"alice-t1@corp.com", "alice"},
		{"alice@corp.com", "alice"},
		{"alice-t0", "alice"},
		{"alice", "alice"},
	}
	for _, c := range cases {
		got := StripTierSuffix(BaseAlias(c.in))
		if got != c.want {
			t.Errorf("StripTierSuffix(BaseAlias(%q)) = %q, want %q", c.in, got, c.want)
		}
	}
}

// helpers for alias dedup tests
func clientIDs(records []Record) []string {
	ids := make([]string, len(records))
	for i, r := range records {
		ids[i] = r.ClientID
	}
	return ids
}

func clientIDSet(records []Record) map[string]bool {
	m := make(map[string]bool, len(records))
	for _, r := range records {
		m[r.ClientID] = true
	}
	return m
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

// ── FilterSincePerSource ──────────────────────────────────────────────────────

var (
	jan15 = time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	jan20 = time.Date(2024, 1, 20, 0, 0, 0, 0, time.UTC)
	feb01 = time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
)

func TestFilterSincePerSource_FiltersTargetFileOnly(t *testing.T) {
	records := []Record{
		// jan.csv: one record before cutoff, one after
		{ClientID: "j1", Source: "jan.csv", TokenCreationTime: jan15.Add(-24 * time.Hour)}, // before — excluded
		{ClientID: "j2", Source: "jan.csv", TokenCreationTime: jan15},                      // on cutoff — kept
		{ClientID: "j3", Source: "jan.csv", TokenCreationTime: jan20},                      // after — kept
		// feb.csv: not in filter map — all kept regardless of date
		{ClientID: "f1", Source: "feb.csv", TokenCreationTime: jan15.Add(-24 * time.Hour)}, // old but kept
		{ClientID: "f2", Source: "feb.csv", TokenCreationTime: feb01},
	}

	sinceBySource := map[string]time.Time{"jan.csv": jan15}
	got := FilterSincePerSource(records, sinceBySource)

	if len(got) != 4 {
		t.Fatalf("expected 4 records, got %d", len(got))
	}
	for _, r := range got {
		if r.ClientID == "j1" {
			t.Error("j1 should have been excluded (before jan.csv cutoff)")
		}
	}
}

func TestFilterSincePerSource_BaseNameMatchesFullPath(t *testing.T) {
	// Source stored as a full path; filter key is just the base name.
	records := []Record{
		{ClientID: "a", Source: "/exports/2024/jan.csv", TokenCreationTime: jan15.Add(-time.Hour)},
		{ClientID: "b", Source: "/exports/2024/jan.csv", TokenCreationTime: jan20},
	}
	sinceBySource := map[string]time.Time{"jan.csv": jan15}
	got := FilterSincePerSource(records, sinceBySource)

	if len(got) != 1 || got[0].ClientID != "b" {
		t.Errorf("expected only record b, got %v", got)
	}
}

func TestFilterSincePerSource_FullPathKeyAlsoMatches(t *testing.T) {
	// Filter key is the full path, not the base name.
	records := []Record{
		{ClientID: "a", Source: "/exports/jan.csv", TokenCreationTime: jan15.Add(-time.Hour)},
		{ClientID: "b", Source: "/exports/jan.csv", TokenCreationTime: jan20},
	}
	sinceBySource := map[string]time.Time{"/exports/jan.csv": jan15}
	got := FilterSincePerSource(records, sinceBySource)

	if len(got) != 1 || got[0].ClientID != "b" {
		t.Errorf("expected only record b, got %v", got)
	}
}

func TestFilterSincePerSource_ZeroCreationTimeAlwaysKept(t *testing.T) {
	// Records with no token_creation_time must not be dropped.
	records := []Record{
		{ClientID: "z", Source: "jan.csv", TokenCreationTime: time.Time{}},
	}
	sinceBySource := map[string]time.Time{"jan.csv": jan15}
	got := FilterSincePerSource(records, sinceBySource)

	if len(got) != 1 {
		t.Error("record with zero TokenCreationTime should be kept")
	}
}

func TestFilterSincePerSource_MultipleFiles(t *testing.T) {
	records := []Record{
		{ClientID: "j1", Source: "jan.csv", TokenCreationTime: jan15.Add(-time.Hour)}, // excluded
		{ClientID: "j2", Source: "jan.csv", TokenCreationTime: jan20},                 // kept
		{ClientID: "f1", Source: "feb.csv", TokenCreationTime: feb01.Add(-time.Hour)}, // excluded
		{ClientID: "f2", Source: "feb.csv", TokenCreationTime: feb01},                 // kept
		{ClientID: "m1", Source: "mar.csv", TokenCreationTime: jan15.Add(-time.Hour)}, // no filter — kept
	}
	sinceBySource := map[string]time.Time{
		"jan.csv": jan15,
		"feb.csv": feb01,
	}
	got := FilterSincePerSource(records, sinceBySource)

	if len(got) != 3 {
		t.Fatalf("expected 3 records, got %d: %v", len(got), got)
	}
	kept := map[string]bool{}
	for _, r := range got {
		kept[r.ClientID] = true
	}
	for _, id := range []string{"j2", "f2", "m1"} {
		if !kept[id] {
			t.Errorf("expected %s to be kept", id)
		}
	}
}

func TestFilterSincePerSource_EmptyMap(t *testing.T) {
	records := []Record{
		{ClientID: "a", Source: "jan.csv", TokenCreationTime: jan15},
	}
	got := FilterSincePerSource(records, nil)
	if len(got) != 1 {
		t.Error("empty sinceBySource should return all records unchanged")
	}
}

// ── input mutation safety ─────────────────────────────────────────────────────
// These tests guard against the records[:0] pattern, which reuses the backing
// array and silently corrupts the caller's slice. Each filter must not modify
// the elements of its input slice.

func TestFilterSince_DoesNotMutateInput(t *testing.T) {
	cutoff := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	records := []Record{
		{ClientID: "old", TokenCreationTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		{ClientID: "new", TokenCreationTime: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)},
	}
	snapshot := []Record{records[0], records[1]}

	_ = FilterSince(records, cutoff)

	if records[0] != snapshot[0] || records[1] != snapshot[1] {
		t.Error("FilterSince modified the input slice's backing array")
	}
}

func TestFilterByNamespace_DoesNotMutateInput(t *testing.T) {
	records := []Record{
		{ClientID: "a", NamespacePath: "education/"},
		{ClientID: "b", NamespacePath: "finance/"},
	}
	snapshot := []Record{records[0], records[1]}

	_ = FilterByNamespace(records, "education")

	if records[0] != snapshot[0] || records[1] != snapshot[1] {
		t.Error("FilterByNamespace modified the input slice's backing array")
	}
}

func TestFilterByClientType_DoesNotMutateInput(t *testing.T) {
	records := []Record{
		{ClientID: "a", ClientType: "entity"},
		{ClientID: "b", ClientType: "non-entity"},
	}
	snapshot := []Record{records[0], records[1]}

	_ = FilterByClientType(records, "entity")

	if records[0] != snapshot[0] || records[1] != snapshot[1] {
		t.Error("FilterByClientType modified the input slice's backing array")
	}
}
