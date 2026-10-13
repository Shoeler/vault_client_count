package tfgen

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/vault-csv-normalizer/internal/normalizer"
)

func TestGenerateTF_EmptyGroups(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.tf")
	n, err := GenerateTF(nil, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 stubs, got %d", n)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("expected no file to be written for empty groups")
	}
}

func TestGenerateTF_SingleGroup(t *testing.T) {
	groups := [][]normalizer.Record{
		{
			{
				ClientID:        "ldap-001",
				Source:          "jan.csv",
				MountAccessor:   "auth_ldap_abc",
				MountPath:       "auth/ldap/",
				MountType:       "ldap",
				ClientType:      "entity",
				EntityAliasName: "alice",
			},
			{
				ClientID:        "oidc-001",
				Source:          "jan.csv",
				MountAccessor:   "auth_oidc_xyz",
				MountPath:       "auth/oidc/",
				MountType:       "oidc",
				ClientType:      "entity",
				EntityAliasName: "alice@corp.com",
			},
		},
	}

	out := filepath.Join(t.TempDir(), "out.tf")
	n, err := GenerateTF(groups, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 stub, got %d", n)
	}

	content, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	tf := string(content)

	// One entity resource
	if count := strings.Count(tf, "resource \"vault_identity_entity\""); count != 1 {
		t.Errorf("expected 1 vault_identity_entity resource, got %d", count)
	}
	// Two alias resources (one per record in the group)
	if count := strings.Count(tf, "resource \"vault_identity_entity_alias\""); count != 2 {
		t.Errorf("expected 2 vault_identity_entity_alias resources, got %d", count)
	}
	// Entity name uses base alias (no domain)
	if !strings.Contains(tf, `name = "alice"`) {
		t.Error("expected entity name to be the base alias \"alice\"")
	}
	// LDAP alias name preserved as-is
	if !strings.Contains(tf, `name           = "alice" # ldap`) {
		t.Error("expected LDAP alias name \"alice\"")
	}
	// OIDC alias name preserved as-is (full email)
	if !strings.Contains(tf, `name           = "alice@corp.com" # oidc`) {
		t.Error("expected OIDC alias name \"alice@corp.com\"")
	}
	// Variables declared for both mount accessors
	if !strings.Contains(tf, `variable "accessor_auth_ldap_abc"`) {
		t.Error("expected variable for auth_ldap_abc")
	}
	if !strings.Contains(tf, `variable "accessor_auth_oidc_xyz"`) {
		t.Error("expected variable for auth_oidc_xyz")
	}
}

func TestGenerateTF_MultipleGroups(t *testing.T) {
	groups := [][]normalizer.Record{
		{
			{ClientID: "ldap-001", Source: "jan.csv", MountAccessor: "auth_ldap_abc", MountPath: "auth/ldap/", MountType: "ldap", EntityAliasName: "alice"},
			{ClientID: "oidc-001", Source: "jan.csv", MountAccessor: "auth_oidc_xyz", MountPath: "auth/oidc/", MountType: "oidc", EntityAliasName: "alice@corp.com"},
		},
		{
			{ClientID: "ldap-002", Source: "jan.csv", MountAccessor: "auth_ldap_abc", MountPath: "auth/ldap/", MountType: "ldap", EntityAliasName: "bob"},
			{ClientID: "oidc-002", Source: "jan.csv", MountAccessor: "auth_oidc_xyz", MountPath: "auth/oidc/", MountType: "oidc", EntityAliasName: "bob@corp.com"},
		},
	}

	out := filepath.Join(t.TempDir(), "out.tf")
	n, err := GenerateTF(groups, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 stubs, got %d", n)
	}

	content, _ := os.ReadFile(out)
	tf := string(content)

	if count := strings.Count(tf, "resource \"vault_identity_entity\""); count != 2 {
		t.Errorf("expected 2 vault_identity_entity resources, got %d", count)
	}
	if count := strings.Count(tf, "resource \"vault_identity_entity_alias\""); count != 4 {
		t.Errorf("expected 4 vault_identity_entity_alias resources, got %d", count)
	}
	// Shared mount accessors declared only once each
	if count := strings.Count(tf, `variable "accessor_auth_ldap_abc"`); count != 1 {
		t.Errorf("expected mount accessor variable declared once, got %d", count)
	}
	if count := strings.Count(tf, `variable "accessor_auth_oidc_xyz"`); count != 1 {
		t.Errorf("expected mount accessor variable declared once, got %d", count)
	}
}

func TestGenerateTF_PetnamesAreUnique(t *testing.T) {
	// Build enough groups to exercise multiple petname assignments.
	aliases := []string{"alice", "bob", "carol", "dave", "eve"}
	groups := make([][]normalizer.Record, len(aliases))
	for i, alias := range aliases {
		groups[i] = []normalizer.Record{
			{ClientID: "ldap-" + alias, Source: "jan.csv", MountAccessor: "auth_ldap_abc", MountPath: "auth/ldap/", MountType: "ldap", EntityAliasName: alias},
			{ClientID: "oidc-" + alias, Source: "jan.csv", MountAccessor: "auth_oidc_xyz", MountPath: "auth/oidc/", MountType: "oidc", EntityAliasName: alias + "@corp.com"},
		}
	}

	out := filepath.Join(t.TempDir(), "out.tf")
	_, err := GenerateTF(groups, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(out)
	tf := string(content)

	// Extract resource names and verify uniqueness.
	seen := make(map[string]int)
	for _, line := range strings.Split(tf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "resource \"vault_identity_entity\" ") {
			name := strings.Trim(strings.Fields(line)[2], `"{ `)
			seen[name]++
		}
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("petname %q used %d times — names must be unique", name, count)
		}
	}
}

func TestGenerateTF_GroupedByFile(t *testing.T) {
	groups := [][]normalizer.Record{
		// jan.csv — alice
		{
			{ClientID: "ldap-001", Source: "/data/jan.csv", MountAccessor: "auth_ldap_abc", MountPath: "auth/ldap/", MountType: "ldap", EntityAliasName: "alice"},
			{ClientID: "oidc-001", Source: "/data/jan.csv", MountAccessor: "auth_oidc_xyz", MountPath: "auth/oidc/", MountType: "oidc", EntityAliasName: "alice@corp.com"},
		},
		// feb.csv — alice (same person, different file)
		{
			{ClientID: "ldap-002", Source: "/data/feb.csv", MountAccessor: "auth_ldap_abc", MountPath: "auth/ldap/", MountType: "ldap", EntityAliasName: "alice"},
			{ClientID: "oidc-002", Source: "/data/feb.csv", MountAccessor: "auth_oidc_xyz", MountPath: "auth/oidc/", MountType: "oidc", EntityAliasName: "alice@corp.com"},
		},
		// feb.csv — bob (second group in the same file)
		{
			{ClientID: "ldap-003", Source: "/data/feb.csv", MountAccessor: "auth_ldap_abc", MountPath: "auth/ldap/", MountType: "ldap", EntityAliasName: "bob"},
			{ClientID: "oidc-003", Source: "/data/feb.csv", MountAccessor: "auth_oidc_xyz", MountPath: "auth/oidc/", MountType: "oidc", EntityAliasName: "bob@corp.com"},
		},
	}

	out := filepath.Join(t.TempDir(), "out.tf")
	n, err := GenerateTF(groups, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 stubs, got %d", n)
	}

	content, _ := os.ReadFile(out)
	tf := string(content)

	// File headers present for both source files.
	if !strings.Contains(tf, "Source: jan.csv") {
		t.Error("expected file header for jan.csv")
	}
	if !strings.Contains(tf, "Source: feb.csv") {
		t.Error("expected file header for feb.csv")
	}
	// jan.csv header shows 1 group, feb.csv header shows 2 groups.
	if !strings.Contains(tf, "jan.csv (1 alias group(s))") {
		t.Error("expected jan.csv to show 1 alias group")
	}
	if !strings.Contains(tf, "feb.csv (2 alias group(s))") {
		t.Error("expected feb.csv to show 2 alias groups")
	}
	// jan.csv header appears before feb.csv header.
	if strings.Index(tf, "jan.csv") > strings.Index(tf, "feb.csv") {
		t.Error("expected jan.csv section before feb.csv section")
	}
	// Total: 3 entities, 6 aliases.
	if count := strings.Count(tf, "resource \"vault_identity_entity\""); count != 3 {
		t.Errorf("expected 3 vault_identity_entity resources, got %d", count)
	}
	if count := strings.Count(tf, "resource \"vault_identity_entity_alias\""); count != 6 {
		t.Errorf("expected 6 vault_identity_entity_alias resources, got %d", count)
	}
}

func TestGenerateTF_MissingMountAccessor(t *testing.T) {
	groups := [][]normalizer.Record{
		{
			{ClientID: "ldap-001", Source: "jan.csv", MountAccessor: "", MountPath: "auth/ldap/", MountType: "ldap", EntityAliasName: "alice"},
			{ClientID: "oidc-001", Source: "jan.csv", MountAccessor: "auth_oidc_xyz", MountPath: "auth/oidc/", MountType: "oidc", EntityAliasName: "alice@corp.com"},
		},
	}

	out := filepath.Join(t.TempDir(), "out.tf")
	_, err := GenerateTF(groups, out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	content, _ := os.ReadFile(out)
	tf := string(content)

	// Record with no mount_accessor gets a TODO placeholder, not a var reference.
	if !strings.Contains(tf, `mount_accessor = "TODO"`) {
		t.Error("expected TODO placeholder for missing mount_accessor")
	}
}

// aliasBlock returns the body of resource "vault_identity_entity_alias" "<name>".
func aliasBlock(t *testing.T, tf, name string) string {
	t.Helper()
	head := `resource "vault_identity_entity_alias" "` + name + `" {` + "\n"
	start := strings.Index(tf, head)
	if start < 0 {
		t.Fatalf("missing alias resource %q in:\n%s", name, tf)
	}
	body := tf[start+len(head):]
	return body[:strings.Index(body, "}\n")]
}

func generate(t *testing.T, groups [][]normalizer.Record) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.tf")
	if _, err := GenerateTF(groups, out); err != nil {
		t.Fatalf("GenerateTF: %v", err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	return string(b)
}

var entityRE = regexp.MustCompile(`resource "vault_identity_entity" "([a-z0-9_]+)" \{\n\s*name\s*=\s*"([^"]*)"`)

// ==== P-T1 (new; append to TestGenerateTF_SingleGroup or keep separate) ====
func TestGenerateTF_AliasesLinkToEntityAndOwnAccessor(t *testing.T) {
	tf := generate(t, [][]normalizer.Record{{
		{Source: "jan.csv", MountAccessor: "auth_ldap_abc", MountPath: "auth/ldap/", MountType: "ldap", EntityAliasName: "alice"},
		{Source: "jan.csv", MountAccessor: "auth_oidc_xyz", MountPath: "auth/oidc/", MountType: "oidc", EntityAliasName: "alice@corp.com"},
	}})
	m := entityRE.FindStringSubmatch(tf)
	if m == nil {
		t.Fatalf("no entity resource in:\n%s", tf)
	}
	pet := m[1]
	for i, acc := range []string{"auth_ldap_abc", "auth_oidc_xyz"} {
		body := aliasBlock(t, tf, pet+"_"+strconv.Itoa(i))
		if !regexp.MustCompile(`mount_accessor\s*=\s*var\.accessor_` + acc + `\n`).MatchString(body) {
			t.Errorf("alias %d: expected mount_accessor = var.accessor_%s, got:\n%s", i, acc, body)
		}
		if !regexp.MustCompile(`canonical_id\s*=\s*vault_identity_entity\.` + pet + `\.id\n`).MatchString(body) {
			t.Errorf("alias %d: expected canonical_id to reference vault_identity_entity.%s, got:\n%s", i, pet, body)
		}
		if !regexp.MustCompile(`variable "accessor_` + acc + `" \{\n[^}]*default\s*=\s*"` + acc + `"`).MatchString(tf) {
			t.Errorf("expected variable accessor_%s with default %q", acc, acc)
		}
	}
}

// ==== P-T2 (new) ====
func TestGenerateTF_OIDCEntityNameUsesMetadataUsername(t *testing.T) {
	// The OIDC record comes first, so the entity name is derived from it. Its
	// entity_alias_name is the subject ID; the per-file dedup matched it on
	// entity_alias_metadata.username, so the entity must be named "alice".
	tf := generate(t, [][]normalizer.Record{{
		{Source: "jan.csv", MountAccessor: "auth_oidc_xyz", MountType: "oidc", EntityAliasName: "uuid-1234", EntityAliasMetadataUsername: "alice"},
		{Source: "jan.csv", MountAccessor: "auth_ldap_abc", MountType: "ldap", EntityAliasName: "alice"},
	}})
	m := entityRE.FindStringSubmatch(tf)
	if m == nil || m[2] != "alice" {
		t.Fatalf("expected entity name \"alice\", got %v in:\n%s", m, tf)
	}
	// The OIDC alias keeps the real alias name (the subject), which is what Vault matches on login.
	if body := aliasBlock(t, tf, m[1]+"_0"); !regexp.MustCompile(`name\s*=\s*"uuid-1234" # oidc`).MatchString(body) {
		t.Errorf("expected OIDC alias name uuid-1234, got:\n%s", body)
	}
}

// ==== P-T3 (new) ====
func TestGenerateTF_MethodFallsBackToAuthMethod(t *testing.T) {
	tf := generate(t, [][]normalizer.Record{{
		{Source: "jan.csv", MountAccessor: "auth_ldap_abc", AuthMethod: "ldap", EntityAliasName: "alice"},
		{Source: "jan.csv", MountAccessor: "auth_jwt_def", AuthMethod: "jwt", EntityAliasName: "alice@corp.com"},
	}})
	if !strings.Contains(tf, "# alias: alice | methods: ldap, jwt\n") {
		t.Errorf("expected methods taken from auth_method, got:\n%s", tf)
	}
	if !strings.Contains(tf, `"alice" # ldap`) || !strings.Contains(tf, `"alice@corp.com" # jwt`) {
		t.Errorf("expected per-alias method comments from auth_method, got:\n%s", tf)
	}
}

// ==== P-T4 (new) ====
func TestGenerateTF_WriteErrorReturned(t *testing.T) {
	out := filepath.Join(t.TempDir(), "no-such-dir", "out.tf")
	n, err := GenerateTF([][]normalizer.Record{{
		{Source: "jan.csv", MountType: "ldap", EntityAliasName: "alice"},
		{Source: "jan.csv", MountType: "jwt", EntityAliasName: "alice@corp.com"},
	}}, out)
	if err == nil {
		t.Fatal("expected an error writing into a missing directory")
	}
	if n != 0 {
		t.Errorf("expected 0 stubs reported on error, got %d", n)
	}
}

// ==== P-T5 (new) ====
func TestSanitizeID(t *testing.T) {
	cases := []struct{ in, want string }{
		{"auth_ldap_abc", "auth_ldap_abc"},
		{"auth-LDAP.7f3a", "auth_ldap_7f3a"},
		{"__a--b__", "a_b"},
		{"", ""},
	}
	for _, c := range cases {
		if got := sanitizeID(c.in); got != c.want {
			t.Errorf("sanitizeID(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ==== P-T6 (new) ====
func TestNextPetName_UniqueBeyondWordlist(t *testing.T) {
	used := map[string]struct{}{}
	counter := 0
	n := len(petAdjectives)*len(petNouns) + 3
	for i := 0; i < n; i++ {
		nextPetName(used, &counter)
	}
	if len(used) != n {
		t.Errorf("expected %d unique names, got %d", n, len(used))
	}
}
