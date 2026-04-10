package parser

import (
	"strings"
	"testing"
)

func TestParseReader_StandardColumns(t *testing.T) {
	csv := `client_id,namespace_id,namespace_path,mount_accessor,mount_path,mount_type,auth_method,client_type,token_creation_time,client_first_usage_time
abc-123,root,[root],auth_approle_abc,auth/approle/,approle,approle,entity,2024-01-15T10:00:00Z,2024-01-15T12:00:00Z
def-456,ns1,education/,auth_ldap_xyz,auth/ldap/,ldap,ldap,non-entity,2024-02-01T08:00:00Z,
`
	records, err := parseReader(strings.NewReader(csv), "test.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	r := records[0]
	assertEqual(t, "client_id", "abc-123", r.ClientID)
	assertEqual(t, "namespace_id", "root", r.NamespaceID)
	assertEqual(t, "namespace_path", "[root]", r.NamespacePath)
	assertEqual(t, "mount_accessor", "auth_approle_abc", r.MountAccessor)
	assertEqual(t, "mount_path", "auth/approle/", r.MountPath)
	assertEqual(t, "auth_method", "approle", r.AuthMethod)
	assertEqual(t, "client_type", "entity", r.ClientType)
	assertEqual(t, "token_creation_time", "2024-01-15T10:00:00Z", r.TokenCreationTime)
	assertEqual(t, "client_first_usage_time", "2024-01-15T12:00:00Z", r.ClientFirstUsageTime)

	r2 := records[1]
	assertEqual(t, "client_first_usage_time_empty", "", r2.ClientFirstUsageTime)
}

func TestParseReader_LegacyTimestampColumn(t *testing.T) {
	// Vault < 1.17 used "timestamp" instead of "token_creation_time"
	csv := `client_id,namespace_path,client_type,timestamp
legacy-001,[root],entity,2023-06-01T00:00:00Z
`
	records, err := parseReader(strings.NewReader(csv), "legacy.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	// "timestamp" should be mapped to TokenCreationTime
	assertEqual(t, "token_creation_time (from timestamp)", "2023-06-01T00:00:00Z", records[0].TokenCreationTime)
}

func TestParseReader_SkipsBlankClientID(t *testing.T) {
	csv := `client_id,namespace_path,client_type,token_creation_time
,education/,entity,2024-01-01T00:00:00Z
valid-id,[root],non-entity,2024-01-02T00:00:00Z
`
	records, err := parseReader(strings.NewReader(csv), "test.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record (blank client_id skipped), got %d", len(records))
	}
	assertEqual(t, "client_id", "valid-id", records[0].ClientID)
}

func TestParseReader_MissingRequiredColumn(t *testing.T) {
	csv := `namespace_path,client_type
[root],entity
`
	_, err := parseReader(strings.NewReader(csv), "bad.csv")
	if err == nil {
		t.Fatal("expected error for missing client_id column, got nil")
	}
}

func TestParseReader_CaseInsensitiveHeaders(t *testing.T) {
	csv := `CLIENT_ID,NAMESPACE_PATH,CLIENT_TYPE
id-001,[root],entity
`
	records, err := parseReader(strings.NewReader(csv), "test.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	assertEqual(t, "client_id", "id-001", records[0].ClientID)
}

func TestParseReader_AlternativeColumnNames(t *testing.T) {
	// "namespace" → namespace_path, "type" → client_type
	csv := `client_id,namespace,type,timestamp
alt-001,finance/,non_entity,2024-03-01T00:00:00Z
`
	records, err := parseReader(strings.NewReader(csv), "alt.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	assertEqual(t, "namespace_path", "finance/", records[0].NamespacePath)
	assertEqual(t, "client_type", "non_entity", records[0].ClientType)
}

func TestParseReader_EntityAliasName(t *testing.T) {
	csv := `client_id,namespace_path,client_type,entity_alias_name
id-001,[root],entity,alice@corp.com
id-002,[root],entity,bob-v2
id-003,[root],non-entity,
`
	records, err := parseReader(strings.NewReader(csv), "test.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(records))
	}
	assertEqual(t, "entity_alias_name[0]", "alice@corp.com", records[0].EntityAliasName)
	assertEqual(t, "entity_alias_name[1]", "bob-v2", records[1].EntityAliasName)
	assertEqual(t, "entity_alias_name[2]", "", records[2].EntityAliasName)
}

func TestParseReader_EntityAliasNameAliasColumns(t *testing.T) {
	// alias_name and entity_alias are accepted as column name variants
	for _, colName := range []string{"alias_name", "entity_alias"} {
		csv := "client_id," + colName + "\nid-001,alice-1\n"
		records, err := parseReader(strings.NewReader(csv), "test.csv")
		if err != nil {
			t.Fatalf("col %q: unexpected error: %v", colName, err)
		}
		if len(records) != 1 {
			t.Fatalf("col %q: expected 1 record, got %d", colName, len(records))
		}
		if records[0].EntityAliasName != "alice-1" {
			t.Errorf("col %q: EntityAliasName = %q, want %q", colName, records[0].EntityAliasName, "alice-1")
		}
	}
}

func assertEqual(t *testing.T, field, want, got string) {
	t.Helper()
	if want != got {
		t.Errorf("%s: want %q, got %q", field, want, got)
	}
}
