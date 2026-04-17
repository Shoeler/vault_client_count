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
		got := ParseTime(c.in)
		if !got.Equal(c.want) {
			t.Errorf("ParseTime(%q) = %v, want %v", c.in, got, c.want)
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
		{"-t0", ""},   // degenerate: only the suffix
		{"t0", "t0"},  // no hyphen
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
	// The combination used by aliasKeyFor: strip domain then tier.
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

func TestDeduplicateByAlias_CollapsesSameBaseAcrossAccessors(t *testing.T) {
	// "sbishop", "sbishop@hashicorp.com", "sbishop-t0", "sbishop-t1", and
	// "sbishop" in a second file all normalize to "sbishop" → only the first
	// occurrence across all files is kept.
	records := []Record{
		{ClientID: "1", EntityAliasName: "sbishop", MountAccessor: "auth_ldap_abc123", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "sbishop@hashicorp.com", MountAccessor: "auth_jwt_def456", Source: "jan.csv"}, // dup: normalizes to "sbishop"
		{ClientID: "3", EntityAliasName: "sbishop-t0", MountAccessor: "auth_ldap_abc123", Source: "jan.csv"},           // dup: tier stripped → "sbishop"
		{ClientID: "4", EntityAliasName: "sbishop-t1", MountAccessor: "auth_oidc_xyz789", Source: "jan.csv"},           // dup: tier stripped → "sbishop"
		{ClientID: "5", EntityAliasName: "sbishop", MountAccessor: "auth_ldap_abc123", Source: "feb.csv"},              // dup: same normalized alias across files
		{ClientID: "6", EntityAliasName: ""},                                                                            // kept: blank always kept
	}
	out := DeduplicateByAlias(records)
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	for _, id := range []string{"1", "6"} {
		if !kept[id] {
			t.Errorf("expected ClientID=%s to be kept", id)
		}
	}
	for _, id := range []string{"2", "3", "4", "5"} {
		if kept[id] {
			t.Errorf("expected ClientID=%s to be dropped", id)
		}
	}
}

func TestDeduplicateByAlias_KeepsAllBlanks(t *testing.T) {
	records := []Record{
		{ClientID: "1", EntityAliasName: ""},
		{ClientID: "2", EntityAliasName: ""},
		{ClientID: "3", EntityAliasName: "alice@corp.com", Source: "jan.csv"},
	}
	out := DeduplicateByAlias(records)
	if len(out) != 3 {
		t.Fatalf("expected 3 records (2 blanks + 1 aliased), got %d", len(out))
	}
}

func TestFindAliasDuplicates_SameBaseAcrossAccessors(t *testing.T) {
	// "sbishop", "sbishop@hashicorp.com", "sbishop-t0", and "sbishop" in a
	// second file all normalize to "sbishop" → one group with 4 members.
	records := []Record{
		{ClientID: "1", EntityAliasName: "sbishop", MountAccessor: "auth_ldap_abc123", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "sbishop@hashicorp.com", MountAccessor: "auth_jwt_def456", Source: "jan.csv"},
		{ClientID: "3", EntityAliasName: "sbishop-t0", MountAccessor: "auth_ldap_abc123", Source: "jan.csv"},
		{ClientID: "4", EntityAliasName: "sbishop", MountAccessor: "auth_ldap_abc123", Source: "feb.csv"}, // cross-file dup
		{ClientID: "5", EntityAliasName: ""},                                                               // ignored
	}
	groups := FindAliasDuplicates(records)
	if len(groups) != 1 {
		t.Fatalf("expected 1 duplicate group, got %d", len(groups))
	}
	if len(groups[0]) != 4 {
		t.Errorf("expected 4 members in group, got %d", len(groups[0]))
	}
	for _, r := range groups[0] {
		if StripTierSuffix(BaseAlias(r.EntityAliasName)) != "sbishop" {
			t.Errorf("unexpected record in group: %+v", r)
		}
	}
}

func TestFindAliasDuplicates_NoDuplicates(t *testing.T) {
	// All different normalized aliases — no duplicates regardless of file.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "bob", Source: "jan.csv"},
		{ClientID: "3", EntityAliasName: "carol", Source: "feb.csv"},
		{ClientID: "4", EntityAliasName: ""},
	}
	groups := FindAliasDuplicates(records)
	if len(groups) != 0 {
		t.Errorf("expected no duplicate groups, got %d", len(groups))
	}
}

func TestDeduplicateByAlias_IgnoresPKIClients(t *testing.T) {
	// PKI clients are always kept regardless of alias duplication.
	// Non-PKI clients with the same base alias in the same file are deduplicated.
	records := []Record{
		{ClientID: "1", EntityAliasName: "abc-123", ClientType: "acme", Source: "jan.csv"},  // PKI, kept
		{ClientID: "2", EntityAliasName: "abc-456", ClientType: "acme", Source: "jan.csv"},  // PKI, kept (not deduped)
		{ClientID: "3", EntityAliasName: "abc-789", MountAccessor: "auth_cert_xyz", Source: "jan.csv"}, // cert auth — PKI, kept
		{ClientID: "4", EntityAliasName: "alice@corp", Source: "jan.csv"},                   // non-PKI, first: kept
		{ClientID: "5", EntityAliasName: "alice@example.com", Source: "jan.csv"},            // non-PKI dup: base "alice" already seen, dropped
	}
	out := DeduplicateByAlias(records)
	if len(out) != 4 {
		t.Fatalf("expected 4 records (3 PKI/cert + 1 non-PKI), got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	for _, id := range []string{"1", "2", "3", "4"} {
		if !kept[id] {
			t.Errorf("expected ClientID=%s to be kept", id)
		}
	}
	if kept["5"] {
		t.Errorf("expected ClientID=5 (non-PKI dup) to be dropped")
	}
}

func TestFindAliasDuplicates_IgnoresPKIClients(t *testing.T) {
	records := []Record{
		{ClientID: "1", EntityAliasName: "abc-123", ClientType: "acme", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "abc-456", ClientType: "acme", Source: "jan.csv"},
		{ClientID: "3", EntityAliasName: "abc-789", MountAccessor: "auth_cert_xyz", Source: "jan.csv"},
	}
	groups := FindAliasDuplicates(records)
	if len(groups) != 0 {
		t.Errorf("expected no duplicate groups (all PKI/cert), got %d", len(groups))
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
		{ClientID: "j2", Source: "jan.csv", TokenCreationTime: jan15},                       // on cutoff — kept
		{ClientID: "j3", Source: "jan.csv", TokenCreationTime: jan20},                       // after — kept
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

// ── JWT deduplication ─────────────────────────────────────────────────────────

func TestDeduplicateJWT_DropsJWTMatchingNonJWT(t *testing.T) {
	// alice authenticates via LDAP (kept) and JWT (dropped — same normalized alias).
	// bob has only a JWT record (kept — no non-JWT match).
	// carol has a JWT record with no alias (always kept).
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", MountType: "jwt", Source: "jan.csv"}, // dropped: normalizes to "alice", matches LDAP
		{ClientID: "3", EntityAliasName: "bob@corp.com", MountType: "jwt", Source: "jan.csv"},   // kept: no non-JWT match for "bob"
		{ClientID: "4", EntityAliasName: "", MountType: "jwt", Source: "jan.csv"},               // kept: blank alias always kept
	}
	out := DeduplicateJWT(records)
	if len(out) != 3 {
		t.Fatalf("expected 3 records, got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	for _, id := range []string{"1", "3", "4"} {
		if !kept[id] {
			t.Errorf("expected ClientID=%s to be kept", id)
		}
	}
	if kept["2"] {
		t.Error("expected ClientID=2 (JWT dup of LDAP alice) to be dropped")
	}
}

func TestDeduplicateJWT_TierNormalizationApplied(t *testing.T) {
	// LDAP alias is "alice-t0" (normalizes to "alice").
	// JWT alias is "alice@corp.com" (normalizes to "alice").
	// They match → JWT dropped.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice-t0", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", MountType: "jwt", Source: "jan.csv"},
	}
	out := DeduplicateJWT(records)
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d: %v", len(out), clientIDs(out))
	}
	if out[0].ClientID != "1" {
		t.Errorf("expected LDAP record to be kept, got ClientID=%s", out[0].ClientID)
	}
}

func TestDeduplicateJWT_MatchesAcrossFiles(t *testing.T) {
	// JWT record in feb.csv matches an LDAP alias in jan.csv — cross-file match
	// is intentional, JWT record is dropped.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", MountType: "jwt", Source: "feb.csv"},
	}
	out := DeduplicateJWT(records)
	if len(out) != 1 {
		t.Fatalf("expected 1 record (cross-file JWT match dropped), got %d", len(out))
	}
	if out[0].ClientID != "1" {
		t.Errorf("expected LDAP record kept, got ClientID=%s", out[0].ClientID)
	}
}

func TestDeduplicateJWT_AuthMethodFallback(t *testing.T) {
	// JWT identified via auth_method rather than mount_type.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", AuthMethod: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", AuthMethod: "jwt", Source: "jan.csv"},
	}
	out := DeduplicateJWT(records)
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d: %v", len(out), clientIDs(out))
	}
	if out[0].ClientID != "1" {
		t.Errorf("expected LDAP record kept, got ClientID=%s", out[0].ClientID)
	}
}

func TestDeduplicateJWT_NonJWTRecordsUnaffected(t *testing.T) {
	// No JWT records — nothing should be dropped.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "bob", MountType: "oidc", Source: "jan.csv"},
	}
	out := DeduplicateJWT(records)
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d", len(out))
	}
}

// ── combined alias + client_id deduplication ─────────────────────────────────

func TestDeduplicateByAlias_ThenDeduplicate_CollapsesBothDimensions(t *testing.T) {
	// --dedup-alias runs first (within-file tier/domain collapse), then -d
	// (cross-file client_id collapse). Together they handle the case where the
	// same person appears as different alias variants in the same file AND as the
	// same client_id across multiple files.
	//
	// jan.csv: alice (id:1) and alice-t0 (id:2) → alias dedup keeps id:1, drops id:2
	// feb.csv: alice (id:1) → same client_id as jan.csv survivor → -d drops it
	// jan.csv: bob (id:3) → distinct alias and id → kept throughout
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice-t0", Source: "jan.csv"}, // dropped by alias dedup (tier → "alice")
		{ClientID: "1", EntityAliasName: "alice", Source: "feb.csv"},    // dropped by -d (same id as jan survivor)
		{ClientID: "3", EntityAliasName: "bob", Source: "jan.csv"},
	}

	afterAlias := DeduplicateByAlias(records)
	afterBoth := Deduplicate(afterAlias)

	if len(afterBoth) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(afterBoth), clientIDs(afterBoth))
	}
	kept := clientIDSet(afterBoth)
	if !kept["1"] {
		t.Error("expected id:1 to be kept")
	}
	if !kept["3"] {
		t.Error("expected id:3 to be kept")
	}
	if kept["2"] {
		t.Error("expected id:2 to be dropped by alias dedup")
	}
}

func TestDeduplicateByAlias_CollapsesAcrossFiles(t *testing.T) {
	// alice-t0 in jan.csv and alice-t1 in feb.csv both normalize to "alice" →
	// alias dedup keeps only the first occurrence regardless of file.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice-t0", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice-t1", Source: "feb.csv"},
	}

	out := DeduplicateByAlias(records)

	if len(out) != 1 {
		t.Fatalf("expected 1 record (cross-file tier collapse), got %d", len(out))
	}
	if out[0].ClientID != "1" {
		t.Errorf("expected first occurrence (id:1) to be kept, got id:%s", out[0].ClientID)
	}
}

// Regression: tiered accounts across files must be collapsed.
// Before the fix, aliasKey included the source filename, so alice-t0 in
// jan.csv and alice in feb.csv hashed to different keys and were never
// compared — each was counted as a separate client.
func TestDeduplicateByAlias_TieredAccountsAcrossFiles(t *testing.T) {
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice-t0", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice", Source: "feb.csv"},    // same person, different tier label
		{ClientID: "3", EntityAliasName: "alice-t1", Source: "mar.csv"}, // same person, third file
		{ClientID: "4", EntityAliasName: "bob", Source: "jan.csv"},      // different person, kept
	}
	out := DeduplicateByAlias(records)
	if len(out) != 2 {
		t.Fatalf("expected 2 records (alice collapsed to 1, bob kept), got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	if !kept["1"] {
		t.Error("expected first alice occurrence (id:1) to be kept")
	}
	if !kept["4"] {
		t.Error("expected bob (id:4) to be kept")
	}
	for _, id := range []string{"2", "3"} {
		if kept[id] {
			t.Errorf("expected ClientID=%s (tier variant of alice) to be dropped", id)
		}
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
