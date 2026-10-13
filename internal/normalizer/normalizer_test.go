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

// Abandoned-client removal applies only to client_type entity (commit ee2570e):
// non-entity and acme records are never removed, even with blank identity fields.
func TestFilterAbandonedClients(t *testing.T) {
	records := []Record{
		// removed as merged/deleted: mount path present
		{ClientID: "drop-merged-1", ClientType: "entity", EntityName: "", EntityAliasName: "", MountPath: "auth/ldap/", MountType: "ldap"},
		// removed as merged/deleted: mount path present even if mount type is blank
		{ClientID: "drop-merged-2", ClientType: "entity", EntityName: "", EntityAliasName: "", MountPath: "auth/oidc/", MountType: ""},
		// removed as no mount: mount path missing
		{ClientID: "drop-nomount-1", ClientType: "entity", EntityName: "", EntityAliasName: "", MountPath: "", MountType: "ldap"},
		// removed as merged/deleted PKI (auth_cert accessor, mount present)
		{ClientID: "drop-merged-pki-1", ClientType: "entity", EntityName: "", EntityAliasName: "", MountPath: "auth/cert/", MountType: "cert", MountAccessor: "auth_cert_abc123"},
		// removed as no-mount PKI (auth_cert accessor, mount missing)
		{ClientID: "drop-nomount-pki-1", ClientType: "entity", EntityName: "", EntityAliasName: "", MountPath: "", MountType: "cert", MountAccessor: "auth_cert_xyz789"},
		// keep: not an entity client, even though identity fields are blank
		{ClientID: "keep-nonentity-1", ClientType: "non-entity", EntityName: "", EntityAliasName: "", MountPath: "", MountType: "token"},
		// keep: ACME client, even though identity fields are blank
		{ClientID: "keep-acme-1", ClientType: "acme", EntityName: "", EntityAliasName: "", MountPath: "pki/"},
		// keep: entity name present
		{ClientID: "keep-3", ClientType: "entity", EntityName: "Alice", EntityAliasName: "", MountPath: "auth/ldap/", MountType: "ldap"},
		// keep: entity alias present
		{ClientID: "keep-4", ClientType: "entity", EntityName: "", EntityAliasName: "alice", MountPath: "auth/ldap/", MountType: "ldap"},
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
	if len(out) != 4 {
		t.Fatalf("expected 4 records after filter, got %d", len(out))
	}
	present := make(map[string]bool, len(out))
	for _, r := range out {
		present[r.ClientID] = true
	}
	for _, id := range []string{"keep-nonentity-1", "keep-acme-1", "keep-3", "keep-4"} {
		if !present[id] {
			t.Errorf("expected %q to be kept", id)
		}
	}
	for _, r := range out {
		if strings.HasPrefix(r.ClientID, "drop-") {
			t.Fatal("drop-* records should have been removed")
		}
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
		{ClientID: "6", EntityAliasName: ""}, // kept: blank always kept
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
		{ClientID: "5", EntityAliasName: ""}, // ignored
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
		{ClientID: "1", EntityAliasName: "abc-123", ClientType: "acme", Source: "jan.csv"},             // PKI, kept
		{ClientID: "2", EntityAliasName: "abc-456", ClientType: "acme", Source: "jan.csv"},             // PKI, kept (not deduped)
		{ClientID: "3", EntityAliasName: "abc-789", MountAccessor: "auth_cert_xyz", Source: "jan.csv"}, // cert auth — PKI, kept
		{ClientID: "4", EntityAliasName: "alice@corp", Source: "jan.csv"},                              // non-PKI, first: kept
		{ClientID: "5", EntityAliasName: "alice@example.com", Source: "jan.csv"},                       // non-PKI dup: base "alice" already seen, dropped
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

func TestDeduplicateByAlias_CollapseOIDCWithLDAP(t *testing.T) {
	// LDAP and OIDC share the same identity group, so the same normalized alias
	// across both auth methods is treated as one client.
	// JWT remains a separate group and is not collapsed here.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", MountType: "oidc", Source: "jan.csv"}, // dup: ldap/oidc group, normalizes to "alice"
		{ClientID: "3", EntityAliasName: "alice-t0", MountType: "ldap", Source: "feb.csv"},       // dup: ldap/oidc group, tier stripped → "alice"
		{ClientID: "4", EntityAliasName: "alice@corp.com", MountType: "jwt", Source: "jan.csv"},  // kept: jwt is a separate group
		{ClientID: "5", EntityAliasName: "bob", MountType: "ldap", Source: "jan.csv"},            // kept: different alias
	}
	out := DeduplicateByAlias(records)
	if len(out) != 3 {
		t.Fatalf("expected 3 records, got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	for _, id := range []string{"1", "4", "5"} {
		if !kept[id] {
			t.Errorf("expected ClientID=%s to be kept", id)
		}
	}
	for _, id := range []string{"2", "3"} {
		if kept[id] {
			t.Errorf("expected ClientID=%s to be dropped (same ldap/oidc group)", id)
		}
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

// ── method-scoped alias deduplication ────────────────────────────────────────

func TestDeduplicateByAliasForMethods_LDAPAndOIDCGroup(t *testing.T) {
	// Same as -dedup-alias LDAP/OIDC behavior, but specified explicitly.
	// alice via LDAP is kept; alice@corp.com via OIDC is dropped (same group).
	// alice via JWT is kept (not in the group).
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", MountType: "oidc", Source: "jan.csv"}, // dropped
		{ClientID: "3", EntityAliasName: "alice-t0", MountType: "ldap", Source: "feb.csv"},       // dropped: tier stripped
		{ClientID: "4", EntityAliasName: "alice@corp.com", MountType: "jwt", Source: "jan.csv"},  // kept: jwt not in group
		{ClientID: "5", EntityAliasName: "bob", MountType: "ldap", Source: "jan.csv"},            // kept: different alias
	}
	groups := [][]string{{"ldap", "oidc"}}
	out := DeduplicateByAliasForMethods(records, groups)
	if len(out) != 3 {
		t.Fatalf("expected 3 records, got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	for _, id := range []string{"1", "4", "5"} {
		if !kept[id] {
			t.Errorf("expected ClientID=%s to be kept", id)
		}
	}
	for _, id := range []string{"2", "3"} {
		if kept[id] {
			t.Errorf("expected ClientID=%s to be dropped", id)
		}
	}
}

func TestDeduplicateByAliasForMethods_MethodsNotInGroupPassThrough(t *testing.T) {
	// approle records are not in any group and must pass through untouched,
	// even if two share the same alias.
	records := []Record{
		{ClientID: "1", EntityAliasName: "svc-account", MountType: "approle", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "svc-account", MountType: "approle", Source: "jan.csv"}, // NOT deduped
		{ClientID: "3", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "4", EntityAliasName: "alice@corp.com", MountType: "oidc", Source: "jan.csv"}, // dropped
	}
	groups := [][]string{{"ldap", "oidc"}}
	out := DeduplicateByAliasForMethods(records, groups)
	if len(out) != 3 {
		t.Fatalf("expected 3 records (2 approle + 1 ldap), got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	for _, id := range []string{"1", "2", "3"} {
		if !kept[id] {
			t.Errorf("expected ClientID=%s to be kept", id)
		}
	}
	if kept["4"] {
		t.Error("expected ClientID=4 (oidc dup) to be dropped")
	}
}

func TestDeduplicateByAliasForMethods_MultipleIndependentGroups(t *testing.T) {
	// Group 1: {ldap, oidc}; Group 2: {jwt, saml}
	// alice/ldap and alice/oidc collapse → 1 kept
	// alice/jwt and alice/saml collapse → 1 kept
	// The two groups don't interact with each other.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", MountType: "oidc", Source: "jan.csv"}, // dropped (group 1)
		{ClientID: "3", EntityAliasName: "alice@corp.com", MountType: "jwt", Source: "jan.csv"},  // kept (group 2 first)
		{ClientID: "4", EntityAliasName: "alice", MountType: "saml", Source: "jan.csv"},          // dropped (group 2)
		{ClientID: "5", EntityAliasName: "bob", MountType: "ldap", Source: "jan.csv"},            // kept: different alias
	}
	groups := [][]string{{"ldap", "oidc"}, {"jwt", "saml"}}
	out := DeduplicateByAliasForMethods(records, groups)
	if len(out) != 3 {
		t.Fatalf("expected 3 records, got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	for _, id := range []string{"1", "3", "5"} {
		if !kept[id] {
			t.Errorf("expected ClientID=%s to be kept", id)
		}
	}
	for _, id := range []string{"2", "4"} {
		if kept[id] {
			t.Errorf("expected ClientID=%s to be dropped", id)
		}
	}
}

func TestDeduplicateByAliasForMethods_ThreeMethodsOneGroup(t *testing.T) {
	// ldap, oidc, jwt all in one group — alice across all three collapses to 1.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", MountType: "oidc", Source: "jan.csv"}, // dropped
		{ClientID: "3", EntityAliasName: "alice@corp.com", MountType: "jwt", Source: "jan.csv"},  // dropped
		{ClientID: "4", EntityAliasName: "bob", MountType: "jwt", Source: "jan.csv"},             // kept: different alias
	}
	groups := [][]string{{"ldap", "oidc", "jwt"}}
	out := DeduplicateByAliasForMethods(records, groups)
	if len(out) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	if !kept["1"] {
		t.Error("expected id:1 (alice ldap, first occurrence) to be kept")
	}
	if !kept["4"] {
		t.Error("expected id:4 (bob) to be kept")
	}
}

func TestDeduplicateByAliasForMethods_BlankAliasAlwaysKept(t *testing.T) {
	records := []Record{
		{ClientID: "1", EntityAliasName: "", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "", MountType: "oidc", Source: "jan.csv"},
		{ClientID: "3", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
	}
	groups := [][]string{{"ldap", "oidc"}}
	out := DeduplicateByAliasForMethods(records, groups)
	if len(out) != 3 {
		t.Fatalf("expected 3 records (2 blank + 1 aliased), got %d", len(out))
	}
}

func TestDeduplicateByAliasForMethods_PKIClientsAlwaysKept(t *testing.T) {
	records := []Record{
		{ClientID: "1", EntityAliasName: "abc-123", ClientType: "acme", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "abc-123", ClientType: "acme", MountType: "oidc", Source: "jan.csv"},
		{ClientID: "3", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "4", EntityAliasName: "alice@corp.com", MountType: "oidc", Source: "jan.csv"}, // dropped
	}
	groups := [][]string{{"ldap", "oidc"}}
	out := DeduplicateByAliasForMethods(records, groups)
	if len(out) != 3 {
		t.Fatalf("expected 3 records (2 PKI + 1 non-PKI), got %d: %v", len(out), clientIDs(out))
	}
	kept := clientIDSet(out)
	for _, id := range []string{"1", "2", "3"} {
		if !kept[id] {
			t.Errorf("expected ClientID=%s to be kept", id)
		}
	}
	if kept["4"] {
		t.Error("expected ClientID=4 to be dropped")
	}
}

func TestDeduplicateByAliasForMethods_AuthMethodFallback(t *testing.T) {
	// MountType is blank; dedup should fall back to AuthMethod.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", AuthMethod: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", AuthMethod: "oidc", Source: "jan.csv"}, // dropped
	}
	groups := [][]string{{"ldap", "oidc"}}
	out := DeduplicateByAliasForMethods(records, groups)
	if len(out) != 1 {
		t.Fatalf("expected 1 record, got %d: %v", len(out), clientIDs(out))
	}
	if out[0].ClientID != "1" {
		t.Errorf("expected id:1 to be kept, got %s", out[0].ClientID)
	}
}

func TestFindAliasDuplicatesForMethods_ReportsGroupsOnly(t *testing.T) {
	// Only ldap and oidc records should be reported as duplicates.
	// approle records with the same alias are not in the group and not reported.
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice@corp.com", MountType: "oidc", Source: "jan.csv"},
		{ClientID: "3", EntityAliasName: "alice", MountType: "approle", Source: "jan.csv"}, // not in group
	}
	groups := [][]string{{"ldap", "oidc"}}
	dups := FindAliasDuplicatesForMethods(records, groups)
	if len(dups) != 1 {
		t.Fatalf("expected 1 duplicate group, got %d", len(dups))
	}
	if len(dups[0]) != 2 {
		t.Errorf("expected 2 members in group (ldap + oidc), got %d", len(dups[0]))
	}
}

func TestFindAliasDuplicatesForMethods_NoDuplicates(t *testing.T) {
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "bob", MountType: "oidc", Source: "jan.csv"},
	}
	groups := [][]string{{"ldap", "oidc"}}
	dups := FindAliasDuplicatesForMethods(records, groups)
	if len(dups) != 0 {
		t.Errorf("expected no duplicate groups, got %d", len(dups))
	}
}

// ── input mutation safety ─────────────────────────────────────────────────────
// These tests guard against the records[:0] pattern, which reuses the backing
// array and silently corrupts the caller's slice. Each filter must not modify
// the elements of its input slice.

// ── per-file method dedup ─────────────────────────────────────────────────────

func pfRec(id, source, mount, alias string) Record {
	return Record{ClientID: id, Source: source, MountType: mount, EntityAliasName: alias}
}

func pfIDs(records []Record) []string {
	ids := make([]string, 0, len(records))
	for _, r := range records {
		ids = append(ids, r.ClientID)
	}
	return ids
}

func pfExpectIDs(t *testing.T, got []Record, want ...string) {
	t.Helper()
	ids := pfIDs(got)
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("got ids %v, want %v", ids, want)
	}
}

func TestPerFile_SameAliasInTwoFilesNotCollapsed(t *testing.T) {
	records := []Record{
		pfRec("1", "jan.csv", "ldap", "alice"),
		pfRec("2", "feb.csv", "ldap", "alice"),
	}
	groups := [][]string{{"ldap", "oidc"}}
	pfExpectIDs(t, DeduplicateByAliasForMethodsPerFile(records, groups), "1", "2")
	if dups := FindAliasDuplicatesForMethodsPerFile(records, groups); len(dups) != 0 {
		t.Errorf("expected no duplicate groups, got %d", len(dups))
	}
}

func TestPerFile_TierSuffixesAreDistinct(t *testing.T) {
	records := []Record{
		pfRec("1", "jan.csv", "ldap", "alice-t0"),
		pfRec("2", "jan.csv", "ldap", "alice-t1"),
	}
	groups := [][]string{{"ldap"}}
	pfExpectIDs(t, DeduplicateByAliasForMethodsPerFile(records, groups), "1", "2")
	if dups := FindAliasDuplicatesForMethodsPerFile(records, groups); len(dups) != 0 {
		t.Errorf("expected no duplicate groups, got %d", len(dups))
	}
}

func TestPerFile_JWTAndLDAPCollapseInOneFile(t *testing.T) {
	records := []Record{
		pfRec("1", "jan.csv", "ldap", "alice"),
		pfRec("2", "jan.csv", "jwt", "alice@corp.com"),
	}
	groups := [][]string{{"ldap", "jwt"}}
	pfExpectIDs(t, DeduplicateByAliasForMethodsPerFile(records, groups), "1")
	dups := FindAliasDuplicatesForMethodsPerFile(records, groups)
	if len(dups) != 1 || len(dups[0]) != 2 {
		t.Fatalf("expected one group of 2, got %v", dups)
	}
}

func TestPerFile_OIDCUsesMetadataUsername(t *testing.T) {
	oidc := pfRec("2", "jan.csv", "oidc", "uuid-1234")
	oidc.EntityAliasMetadataUsername = "alice"
	records := []Record{pfRec("1", "jan.csv", "ldap", "alice"), oidc}
	groups := [][]string{{"ldap", "oidc"}}
	pfExpectIDs(t, DeduplicateByAliasForMethodsPerFile(records, groups), "1")
	if effectiveAliasInFile(oidc) != "alice" {
		t.Errorf("expected effective alias alice, got %q", effectiveAliasInFile(oidc))
	}
}

func TestPerFile_BlankAliasAlwaysKeptEvenWithMetadataUsername(t *testing.T) {
	oidc := pfRec("2", "jan.csv", "oidc", "")
	oidc.EntityAliasMetadataUsername = "alice"
	records := []Record{pfRec("1", "jan.csv", "ldap", "alice"), oidc}
	groups := [][]string{{"ldap", "oidc"}}
	pfExpectIDs(t, DeduplicateByAliasForMethodsPerFile(records, groups), "1", "2")
	if dups := FindAliasDuplicatesForMethodsPerFile(records, groups); len(dups) != 0 {
		t.Errorf("expected no duplicate groups, got %d", len(dups))
	}
}

func TestPerFile_PKIAlwaysKept(t *testing.T) {
	a := pfRec("1", "jan.csv", "ldap", "alice")
	b := pfRec("2", "jan.csv", "ldap", "alice")
	b.MountAccessor = "auth_cert_abc"
	c := pfRec("3", "jan.csv", "ldap", "alice")
	c.ClientType = "acme"
	groups := [][]string{{"ldap"}}
	pfExpectIDs(t, DeduplicateByAliasForMethodsPerFile([]Record{a, b, c}, groups), "1", "2", "3")
	if dups := FindAliasDuplicatesForMethodsPerFile([]Record{a, b, c}, groups); len(dups) != 0 {
		t.Errorf("expected no duplicate groups, got %d", len(dups))
	}
}

func TestPerFile_MultipleIndependentGroups(t *testing.T) {
	records := []Record{
		pfRec("1", "jan.csv", "ldap", "alice"),
		pfRec("2", "jan.csv", "oidc", "alice"),
		pfRec("3", "jan.csv", "jwt", "alice"),
		pfRec("4", "jan.csv", "saml", "alice"),
	}
	groups := [][]string{{"ldap", "oidc"}, {"jwt", "saml"}}
	pfExpectIDs(t, DeduplicateByAliasForMethodsPerFile(records, groups), "1", "3")
}

func TestPerFileAliasKey(t *testing.T) {
	oidc := Record{MountType: "oidc", EntityAliasName: "uuid", EntityAliasMetadataUsername: "alice@corp.com"}
	cases := []struct {
		r    Record
		want string
	}{
		{Record{MountType: "ldap", EntityAliasName: "alice-t0"}, "alice-t0"},
		{Record{MountType: "jwt", EntityAliasName: "alice@corp.com"}, "alice"},
		{oidc, "alice"},
		{Record{MountType: "oidc", EntityAliasName: "bob"}, "bob"},
	}
	for _, c := range cases {
		if got := PerFileAliasKey(c.r); got != c.want {
			t.Errorf("PerFileAliasKey(%+v) = %q, want %q", c.r, got, c.want)
		}
	}
}

// ── client type mapping, JWT and PKI ──────────────────────────────────────────

func TestDeduplicateJWT_KeepsPKIJWTRecord(t *testing.T) {
	records := []Record{
		{ClientID: "1", MountType: "ldap", EntityAliasName: "alice"},
		{ClientID: "2", MountType: "jwt", EntityAliasName: "alice@corp.com", MountAccessor: "auth_cert_x"},
	}
	pfExpectIDs(t, DeduplicateJWT(records), "1", "2")
}

func TestDeduplicateJWT_CertAliasDoesNotDropJWT(t *testing.T) {
	records := []Record{
		{ClientID: "1", MountType: "cert", EntityAliasName: "alice", MountAccessor: "auth_cert_x"},
		{ClientID: "2", MountType: "jwt", EntityAliasName: "alice@corp.com"},
	}
	pfExpectIDs(t, DeduplicateJWT(records), "1", "2")
}

// ── more input mutation safety ────────────────────────────────────────────────

func TestDedupFunctions_DoNotMutateInput(t *testing.T) {
	build := func() []Record {
		return []Record{
			{ClientID: "a", Source: "x.csv", MountType: "ldap", EntityAliasName: "alice", EntityName: "A"},
			{ClientID: "a", Source: "x.csv", MountType: "jwt", EntityAliasName: "alice@corp.com", MountPath: "auth/jwt/"},
			{ClientID: "b", Source: "x.csv", MountType: "oidc", EntityAliasName: "alice-t0"},
			{ClientID: "c", Source: "x.csv", MountType: "ldap", ClientType: "entity"},
			{ClientID: "d", Source: "x.csv", MountType: "ldap", EntityAliasName: "bob"},
		}
	}
	groups := [][]string{{"ldap", "oidc", "jwt"}}
	funcs := map[string]func([]Record){
		"Deduplicate":                         func(r []Record) { _ = Deduplicate(r) },
		"DeduplicateByAlias":                  func(r []Record) { _ = DeduplicateByAlias(r) },
		"DeduplicateByAliasForMethods":        func(r []Record) { _ = DeduplicateByAliasForMethods(r, groups) },
		"DeduplicateByAliasForMethodsPerFile": func(r []Record) { _ = DeduplicateByAliasForMethodsPerFile(r, groups) },
		"DeduplicateJWT":                      func(r []Record) { _ = DeduplicateJWT(r) },
		"FilterAbandonedClients":              func(r []Record) { _, _ = FilterAbandonedClients(r) },
	}
	for name, fn := range funcs {
		records := build()
		snapshot := build()
		fn(records)
		for i := range records {
			if records[i] != snapshot[i] {
				t.Errorf("%s modified input element %d", name, i)
			}
		}
	}
}

// ==== P-N1 (replaces TestParseTime + TestParseTime_Formats) ====
func TestParseTime(t *testing.T) {
	utc := func(y int, mo time.Month, d, h, mi, s, ns int) time.Time {
		return time.Date(y, mo, d, h, mi, s, ns, time.UTC)
	}
	cases := []struct {
		in   string
		want time.Time
	}{
		{"2024-01-15T10:00:00Z", utc(2024, 1, 15, 10, 0, 0, 0)},
		{"2024-01-15T10:00:00+00:00", utc(2024, 1, 15, 10, 0, 0, 0)},
		{"2024-01-15T12:00:00+02:00", utc(2024, 1, 15, 10, 0, 0, 0)}, // offset converted to UTC
		{"2024-01-15T10:00:00.123456789Z", utc(2024, 1, 15, 10, 0, 0, 123456789)},
		{"2024-01-15T10:00:00", utc(2024, 1, 15, 10, 0, 0, 0)},           // no zone
		{"2024-01-15 10:00:00 +0000 UTC", utc(2024, 1, 15, 10, 0, 0, 0)}, // Go time.String() form
		{"2024-01-15 10:00:00Z", utc(2024, 1, 15, 10, 0, 0, 0)},
		{"2024-01-15", utc(2024, 1, 15, 0, 0, 0, 0)},
		{"06/15/2024", utc(2024, 6, 15, 0, 0, 0, 0)},
		{"  2024-01-15  ", utc(2024, 1, 15, 0, 0, 0, 0)},
		{"", time.Time{}},
		{"0", time.Time{}},
		{"N/A", time.Time{}},
		{"garbage", time.Time{}},
	}
	for _, c := range cases {
		got := ParseTime(c.in)
		if !got.Equal(c.want) {
			t.Errorf("ParseTime(%q) = %v, want %v", c.in, got, c.want)
		}
		if !got.IsZero() && got.Location() != time.UTC {
			t.Errorf("ParseTime(%q) location = %v, want UTC", c.in, got.Location())
		}
	}
}

// ==== P-N2 (replaces TestNormalizeClientType + TestNormalizeClientType_VaultNativeValues) ====
func TestNormalizeClientType(t *testing.T) {
	cases := []struct{ in, want string }{
		{"entity", "entity"},
		{"Entity", "entity"},
		{"ENTITY", "entity"},
		{" entity ", "entity"},
		{"entity client", "entity"},
		{"non-entity", "non-entity"},
		{"non_entity", "non-entity"},
		{"Non-Entity Client", "non-entity"},
		{"non_entity_client", "non-entity"},
		{"nonentity", "non-entity"},
		{"non-entity-token", "non-entity"}, // Vault-native value
		{"acme", "acme"},
		{"acme client", "acme"},
		{"pki-acme", "acme"},           // Vault-native value
		{"certificate", "certificate"}, // passthrough — not an acme alias
		{"cert", "cert"},               // passthrough — not an acme alias
		{"secret-sync", "secret-sync"},
		{"secret_sync", "secret-sync"},
		{"secretsync", "secret-sync"},
		{"secrets sync", "secret-sync"},
		{"secret sync", "secret-sync"},
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

// ==== P-N3 (replaces TestNormalize) ====
func TestNormalize(t *testing.T) {
	raw := []parser.RawRecord{
		{
			Source:                      "exports/jan.csv",
			ClientID:                    "abc-123",
			EntityName:                  "  Alice Smith  ",
			NamespaceID:                 "",
			NamespacePath:               "root",
			MountAccessor:               " auth_approle_1 ",
			MountPath:                   "auth/approle",
			MountType:                   "APPROLE",
			AuthMethod:                  "AppRole",
			ClientType:                  "non_entity",
			TokenCreationTime:           "2024-01-01T00:00:00Z",
			ClientFirstUsageTime:        "2024-01-02",
			EntityAliasName:             " alice@corp.com ",
			EntityAliasMetadataUsername: " alice ",
		},
		{
			Source:        "feb.csv",
			ClientID:      "def-456",
			NamespaceID:   "ns-edu-01",
			NamespacePath: "education",
			MountPath:     "", // stays blank: FilterAbandonedClients and PrintSummary rely on ""
			MountType:     "oidc",
			AuthMethod:    "",
			ClientType:    "",
		},
	}
	want := []Record{
		{
			Source:                      "exports/jan.csv",
			ClientID:                    "abc-123",
			EntityName:                  "Alice Smith",
			NamespaceID:                 "root",
			NamespacePath:               "[root]",
			MountAccessor:               "auth_approle_1",
			MountPath:                   "auth/approle/",
			MountType:                   "approle",
			AuthMethod:                  "approle",
			ClientType:                  "non-entity",
			TokenCreationTime:           time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
			ClientFirstUsageTime:        time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
			EntityAliasName:             "alice@corp.com",
			EntityAliasMetadataUsername: "alice",
		},
		{
			Source:        "feb.csv",
			ClientID:      "def-456",
			NamespaceID:   "ns-edu-01",
			NamespacePath: "education/",
			MountPath:     "",
			MountType:     "oidc",
			AuthMethod:    "",
			ClientType:    "unknown",
		},
	}
	got := Normalize(raw)
	if len(got) != len(want) {
		t.Fatalf("expected %d records, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("record %d:\n  got  %+v\n  want %+v", i, got[i], want[i])
		}
	}
}

// ==== P-N4 (replaces TestFilterByNamespace) ====
func TestFilterByNamespace(t *testing.T) {
	records := []Record{
		{ClientID: "root", NamespacePath: "[root]"},
		{ClientID: "edu", NamespacePath: "education/"},
		{ClientID: "edu-training", NamespacePath: "education/training/"},
		{ClientID: "fin-training", NamespacePath: "Finance/Training/"},
		{ClientID: "fin", NamespacePath: "finance/"},
	}
	cases := []struct {
		substr string
		want   []string
	}{
		{"education", []string{"edu", "edu-training"}},
		{"training", []string{"edu-training", "fin-training"}}, // substring, not prefix
		{"FINANCE", []string{"fin-training", "fin"}},           // case-insensitive
		{"nomatch", nil},
	}
	for _, c := range cases {
		got := clientIDs(FilterByNamespace(records, c.substr))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("FilterByNamespace(%q) = %v, want %v", c.substr, got, c.want)
		}
	}
}

// ==== P-N5 (replaces TestFilterByClientType) ====
func TestFilterByClientType(t *testing.T) {
	records := []Record{
		{ClientID: "e1", ClientType: "entity"},
		{ClientID: "n1", ClientType: "non-entity"},
		{ClientID: "e2", ClientType: "entity"},
		{ClientID: "a1", ClientType: "acme"},
	}
	cases := []struct {
		query string
		want  []string
	}{
		{"entity", []string{"e1", "e2"}},
		{"ENTITY", []string{"e1", "e2"}},
		{"non_entity", []string{"n1"}}, // query goes through the same alias table as the data
		{"pki-acme", []string{"a1"}},
		{"secret-sync", nil},
	}
	for _, c := range cases {
		got := clientIDs(FilterByClientType(records, c.query))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("FilterByClientType(%q) = %v, want %v", c.query, got, c.want)
		}
	}
}

// ==== P-N6 (replaces TestSort) ====
func TestSort(t *testing.T) {
	t1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t2, t3, t4 := t1.AddDate(0, 1, 0), t1.AddDate(0, 2, 0), t1.AddDate(0, 3, 0)
	// Every sort key yields a different permutation of w,x,y,z, so a key that
	// compares the wrong field is detected.
	build := func() []Record {
		return []Record{
			{ClientID: "z", NamespacePath: "zzz/", ClientType: "non-entity", TokenCreationTime: t2, ClientFirstUsageTime: t1, MountAccessor: "auth_d", MountPath: "auth/b/", AuthMethod: "ldap", Source: "a.csv"},
			{ClientID: "y", NamespacePath: "edu/", ClientType: "secret-sync", TokenCreationTime: t1, ClientFirstUsageTime: t2, MountAccessor: "auth_b", MountPath: "auth/d/", AuthMethod: "approle", Source: "c.csv"},
			{ClientID: "x", NamespacePath: "aaa/", ClientType: "acme", TokenCreationTime: t4, ClientFirstUsageTime: t3, MountAccessor: "auth_c", MountPath: "auth/a/", AuthMethod: "oidc", Source: "b.csv"},
			{ClientID: "w", NamespacePath: "[root]", ClientType: "entity", TokenCreationTime: t3, ClientFirstUsageTime: t4, MountAccessor: "auth_a", MountPath: "auth/c/", AuthMethod: "jwt", Source: "d.csv"},
		}
	}
	cases := []struct{ key, want string }{
		{"namespace_path", "w,x,y,z"},
		{"client_type", "x,w,z,y"},
		{"token_creation_time", "y,z,w,x"},
		{"client_first_usage_time", "z,y,x,w"},
		{"mount_accessor", "w,y,x,z"},
		{"mount_path", "x,z,w,y"},
		{"auth_method", "y,w,z,x"},
		{"source", "z,x,y,w"},
		{"  Client_Type ", "x,w,z,y"}, // key is trimmed and case-insensitive
	}
	for _, c := range cases {
		records := build()
		if err := Sort(records, c.key); err != nil {
			t.Fatalf("Sort(%q): %v", c.key, err)
		}
		if got := strings.Join(clientIDs(records), ","); got != c.want {
			t.Errorf("Sort(%q) order = %s, want %s", c.key, got, c.want)
		}
	}
}

// ==== P-N7 (replaces TestStripTierSuffix_AfterBaseAlias) ====
// Domain is stripped before the tier suffix, so "alice-t0@corp.com" reduces to
// "alice" in every global alias path. The old test called the two helpers
// directly and so could not detect the dedup functions composing them wrongly.
func TestAliasNormalization_DomainThenTier(t *testing.T) {
	records := []Record{
		{ClientID: "1", EntityAliasName: "alice", MountType: "ldap", Source: "jan.csv"},
		{ClientID: "2", EntityAliasName: "alice-t0@corp.com", MountType: "ldap", Source: "jan.csv"},
	}
	pfExpectIDs(t, DeduplicateByAlias(records), "1")
	pfExpectIDs(t, DeduplicateByAliasForMethods(records, [][]string{{"ldap"}}), "1")
	jwt := []Record{records[0], {ClientID: "3", EntityAliasName: "alice-t1@corp.com", MountType: "jwt", Source: "jan.csv"}}
	pfExpectIDs(t, DeduplicateJWT(jwt), "1")
}

// ==== P-N8 (replaces the three *_DoesNotMutateInput filter tests) ====
func TestFilterFunctions_DoNotMutateInput(t *testing.T) {
	cutoff := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
	// Every filter drops records[0] and keeps records[1], so an implementation
	// that reuses the input's backing array (out := records[:0]) overwrites
	// records[0] and is detected.
	build := func() []Record {
		return []Record{
			{ClientID: "drop", Source: "jan.csv", NamespacePath: "finance/", ClientType: "non-entity", TokenCreationTime: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
			{ClientID: "keep", Source: "jan.csv", NamespacePath: "education/", ClientType: "entity", TokenCreationTime: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)},
		}
	}
	funcs := map[string]func([]Record) []Record{
		"FilterSince":          func(r []Record) []Record { return FilterSince(r, cutoff) },
		"FilterSincePerSource": func(r []Record) []Record { return FilterSincePerSource(r, map[string]time.Time{"jan.csv": cutoff}) },
		"FilterByNamespace":    func(r []Record) []Record { return FilterByNamespace(r, "education") },
		"FilterByClientType":   func(r []Record) []Record { return FilterByClientType(r, "entity") },
	}
	for name, fn := range funcs {
		records, snapshot := build(), build()
		if got := fn(records); len(got) != 1 || got[0].ClientID != "keep" {
			t.Errorf("%s: expected only \"keep\", got %v", name, clientIDs(got))
		}
		for i := range records {
			if records[i] != snapshot[i] {
				t.Errorf("%s modified input element %d", name, i)
			}
		}
	}
}

// ==== P-N9 (replaces TestPerFile_MethodsOutsideGroupPassThrough) ====
func TestPerFile_MethodsOutsideGroupPassThrough(t *testing.T) {
	records := []Record{
		pfRec("1", "jan.csv", "approle", "svc"),
		pfRec("2", "jan.csv", "approle", "svc"),
	}
	groups := [][]string{{"ldap"}}
	pfExpectIDs(t, DeduplicateByAliasForMethodsPerFile(records, groups), "1", "2")
	// The Find variant feeds --generate-tf; out-of-group records must not be reported.
	if dups := FindAliasDuplicatesForMethodsPerFile(records, groups); len(dups) != 0 {
		t.Errorf("expected no duplicate groups for methods outside the group, got %d", len(dups))
	}
}

// ==== P-N10 (new) ====
func TestPerFile_AuthMethodFallback(t *testing.T) {
	// MountType is blank; per-file dedup falls back to AuthMethod.
	records := []Record{
		{ClientID: "1", Source: "jan.csv", AuthMethod: "ldap", EntityAliasName: "alice"},
		{ClientID: "2", Source: "jan.csv", AuthMethod: "jwt", EntityAliasName: "alice@corp.com"},
	}
	groups := [][]string{{"ldap", "jwt"}}
	pfExpectIDs(t, DeduplicateByAliasForMethodsPerFile(records, groups), "1")
	if dups := FindAliasDuplicatesForMethodsPerFile(records, groups); len(dups) != 1 || len(dups[0]) != 2 {
		t.Errorf("expected one group of 2, got %v", dups)
	}
}

// ==== P-N11 (new) ====
func TestFindAliasDuplicatesForMethods_IgnoresBlankAndPKI(t *testing.T) {
	records := []Record{
		{ClientID: "1", EntityAliasName: "abc-123", ClientType: "acme", MountType: "pki"},
		{ClientID: "2", EntityAliasName: "abc-123", MountAccessor: "auth_cert_x", MountType: "cert"},
		{ClientID: "3", EntityAliasName: "", MountType: "cert"},
		{ClientID: "4", EntityAliasName: "", MountType: "pki"},
	}
	if dups := FindAliasDuplicatesForMethods(records, [][]string{{"cert", "pki"}}); len(dups) != 0 {
		t.Errorf("expected no duplicate groups (PKI and blank aliases are ignored), got %d", len(dups))
	}
}
