package parser

import (
	"strings"
	"testing"
)

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

func TestParseReader_ShortRowTolerated(t *testing.T) {
	csv := "client_id,namespace_path,mount_path,client_type\nabc,ns/,auth/ldap/,entity\ndef,ns/\n"
	records, err := parseReader(strings.NewReader(csv), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[1].ClientID != "def" || records[1].MountPath != "" {
		t.Errorf("unexpected short row result: %+v", records[1])
	}
}

func TestParseReader_BOMHeader(t *testing.T) {
	csv := "\ufeffclient_id,namespace_path\nabc,ns/\n"
	records, err := parseReader(strings.NewReader(csv), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ClientID != "abc" || records[0].NamespacePath != "ns/" {
		t.Errorf("unexpected result: %+v", records)
	}
}

func TestParseReader_BOMBeforeNonClientIDColumn(t *testing.T) {
	csv := "\ufeffnamespace_path,client_id\nns/,abc\n"
	records, err := parseReader(strings.NewReader(csv), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].NamespacePath != "ns/" {
		t.Errorf("unexpected result: %+v", records)
	}
}

func TestParseReader_AliasMetadataUsernameColumn(t *testing.T) {
	csv := "client_id,entity_alias_name,entity_alias_metadata.username\nabc,uuid-1,alice\n"
	records, err := parseReader(strings.NewReader(csv), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if records[0].EntityAliasName != "uuid-1" || records[0].EntityAliasMetadataUsername != "alice" {
		t.Errorf("unexpected result: %+v", records[0])
	}
}

func TestParseReader_DuplicateHeaderFirstWins(t *testing.T) {
	csv := "client_id,mount_path,mount_path\nabc,first/,second/\n"
	records, err := parseReader(strings.NewReader(csv), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if records[0].MountPath != "first/" {
		t.Errorf("expected first/, got %q", records[0].MountPath)
	}
}

func TestParseReader_LegacyColumnAliases(t *testing.T) {
	csv := "client_id,first_seen,mount,auth_backend\nabc,2024-01-01,auth/ldap/,ldap\n"
	records, err := parseReader(strings.NewReader(csv), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	r := records[0]
	if r.ClientFirstUsageTime != "2024-01-01" || r.MountPath != "auth/ldap/" || r.AuthMethod != "ldap" {
		t.Errorf("unexpected result: %+v", r)
	}
}

// ==== P-P1 (replaces TestParseReader_StandardColumns) ====
func TestParseReader_StandardColumns(t *testing.T) {
	csv := `client_id,entity_name,namespace_id,namespace_path,mount_accessor,mount_path,mount_type,auth_method,client_type,token_creation_time,client_first_usage_time
abc-123,Alice Smith,root,[root],auth_approle_abc,auth/approle/,approle,approle,entity,2024-01-15T10:00:00Z,2024-01-15T12:00:00Z
def-456,,ns1,education/,auth_ldap_xyz,auth/ldap/,ldap,,non-entity,2024-02-01T08:00:00Z,
`
	records, err := parseReader(strings.NewReader(csv), "exports/test.csv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	r := records[0]
	assertEqual(t, "source", "exports/test.csv", r.Source)
	assertEqual(t, "client_id", "abc-123", r.ClientID)
	assertEqual(t, "entity_name", "Alice Smith", r.EntityName)
	assertEqual(t, "namespace_id", "root", r.NamespaceID)
	assertEqual(t, "namespace_path", "[root]", r.NamespacePath)
	assertEqual(t, "mount_accessor", "auth_approle_abc", r.MountAccessor)
	assertEqual(t, "mount_path", "auth/approle/", r.MountPath)
	assertEqual(t, "mount_type", "approle", r.MountType)
	assertEqual(t, "auth_method", "approle", r.AuthMethod)
	assertEqual(t, "client_type", "entity", r.ClientType)
	assertEqual(t, "token_creation_time", "2024-01-15T10:00:00Z", r.TokenCreationTime)
	assertEqual(t, "client_first_usage_time", "2024-01-15T12:00:00Z", r.ClientFirstUsageTime)

	r2 := records[1]
	assertEqual(t, "entity_name_empty", "", r2.EntityName)
	assertEqual(t, "mount_type[1]", "ldap", r2.MountType) // differs from auth_method so a swapped mapping is caught
	assertEqual(t, "auth_method_empty", "", r2.AuthMethod)
	assertEqual(t, "client_first_usage_time_empty", "", r2.ClientFirstUsageTime)
}

// ==== P-P2 (new) ====
func TestParseReader_TrimsHeaderAndValueWhitespace(t *testing.T) {
	csv := "client_id ,mount_type ,entity_alias_name\nabc ,ldap , alice \n"
	records, err := parseReader(strings.NewReader(csv), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	r := records[0]
	if r.ClientID != "abc" || r.MountType != "ldap" || r.EntityAliasName != "alice" {
		t.Errorf("expected trimmed values, got %+v", r)
	}
}

// ==== P-P3 (new) ====
func TestParseReader_EmptyInputIsError(t *testing.T) {
	if _, err := parseReader(strings.NewReader(""), "empty.csv"); err == nil {
		t.Fatal("expected an error for a file with no header row")
	}
}

// ==== P-P4 (new) — the testdata fixtures are currently not used by any test ====
func TestParseFile_Fixtures(t *testing.T) {
	cases := []struct {
		path      string
		wantN     int
		wantFirst string // token_creation_time of the first row
	}{
		{"../../testdata/export-2024-01.csv", 9, "2024-01-05T08:12:34Z"},
		{"../../testdata/export-2024-02-legacy.csv", 4, "2024-02-03T09:00:00Z"}, // legacy "timestamp" column
	}
	for _, c := range cases {
		records, err := ParseFile(c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if len(records) != c.wantN {
			t.Fatalf("%s: expected %d records, got %d", c.path, c.wantN, len(records))
		}
		if records[0].TokenCreationTime != c.wantFirst {
			t.Errorf("%s: first token_creation_time = %q, want %q", c.path, records[0].TokenCreationTime, c.wantFirst)
		}
		for _, r := range records {
			if r.Source != c.path {
				t.Errorf("%s: record %s has Source %q", c.path, r.ClientID, r.Source)
			}
		}
	}
	if _, err := ParseFile("../../testdata/does-not-exist.csv"); err == nil {
		t.Error("expected an error for a missing file")
	}
}

// captureWarnings redirects parser warnings into a buffer for the duration of
// the test.
func captureWarnings(t *testing.T) *strings.Builder {
	t.Helper()
	var buf strings.Builder
	prev := warnOut
	warnOut = &buf
	t.Cleanup(func() { warnOut = prev })
	return &buf
}

// An unterminated opening quote used to make the csv reader swallow every
// following line into one field, silently losing those rows. Each physical
// line must now yield its own record, and the bad line must be reported.
func TestParseReader_UnterminatedQuoteDoesNotSwallowRows(t *testing.T) {
	for _, eol := range []string{"\n", "\r\n"} {
		warn := captureWarnings(t)
		in := strings.Join([]string{
			"client_id,entity_name,mount_type,entity_alias_name",
			"c1,Alice,ldap,alice",
			`c2,"Bob Jones,ldap,bob`, // opening quote never closed
			"c3,Carol,ldap,carol",
			"c4,Dan,oidc,dan",
		}, eol) + eol
		records, err := parseReader(strings.NewReader(in), "t.csv")
		if err != nil {
			t.Fatalf("eol %q: unexpected error: %v", eol, err)
		}
		var ids []string
		for _, r := range records {
			ids = append(ids, r.ClientID)
		}
		if got := strings.Join(ids, ","); got != "c1,c2,c3,c4" {
			t.Fatalf("eol %q: client IDs = %s, want c1,c2,c3,c4", eol, got)
		}
		bad := records[1]
		if bad.EntityName != "Bob Jones" || bad.MountType != "ldap" || bad.EntityAliasName != "bob" {
			t.Errorf("eol %q: recovered row = %+v", eol, bad)
		}
		if records[2].EntityName != "Carol" || records[3].MountType != "oidc" {
			t.Errorf("eol %q: rows after the bad line were altered: %+v", eol, records[2:])
		}
		w := warn.String()
		if !strings.Contains(w, "t.csv line 3: unterminated quoted field") || strings.Count(w, "warning:") != 1 {
			t.Errorf("eol %q: expected one warning naming line 3, got %q", eol, w)
		}
	}
}

func TestParseReader_UnterminatedQuoteOnLastLineWithoutNewline(t *testing.T) {
	warn := captureWarnings(t)
	in := "client_id,entity_name,mount_type\nc1,Alice,ldap\nc2,\"Bob,ldap"
	records, err := parseReader(strings.NewReader(in), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[1].ClientID != "c2" || records[1].MountType != "ldap" {
		t.Fatalf("expected c1 and recovered c2, got %+v", records)
	}
	if !strings.Contains(warn.String(), "t.csv line 3:") {
		t.Errorf("expected a warning naming line 3, got %q", warn.String())
	}
}

func TestParseReader_UnterminatedQuoteInHeaderIsError(t *testing.T) {
	captureWarnings(t)
	in := "client_id,\"entity_name,mount_type\nc1,Alice,ldap\n"
	if _, err := parseReader(strings.NewReader(in), "t.csv"); err == nil {
		t.Fatal("expected an error for an unterminated quote in the header")
	}
}

// LazyQuotes tolerance is kept: a stray quote inside an unquoted field is a
// literal character, not the start of a quoted field.
func TestParseReader_StrayQuoteInsideFieldTolerated(t *testing.T) {
	warn := captureWarnings(t)
	in := "client_id,entity_name,mount_type\nc1,O\"Brien,ldap\nc2,Bob,oidc\n"
	records, err := parseReader(strings.NewReader(in), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	assertEqual(t, "entity_name", `O"Brien`, records[0].EntityName)
	assertEqual(t, "mount_type", "ldap", records[0].MountType)
	assertEqual(t, "client_id[1]", "c2", records[1].ClientID)
	if warn.Len() != 0 {
		t.Errorf("expected no warnings, got %q", warn.String())
	}
}

func TestParseReader_QuotedFieldWithComma(t *testing.T) {
	warn := captureWarnings(t)
	in := "client_id,entity_name,mount_type\nc1,\"Smith, Alice\",ldap\nc2,\"Say \"\"hi\"\"\",oidc\n"
	records, err := parseReader(strings.NewReader(in), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	assertEqual(t, "entity_name", "Smith, Alice", records[0].EntityName)
	assertEqual(t, "mount_type", "ldap", records[0].MountType)
	assertEqual(t, "entity_name[1]", `Say "hi"`, records[1].EntityName)
	if warn.Len() != 0 {
		t.Errorf("expected no warnings, got %q", warn.String())
	}
}

func TestParseReader_ClientFirstUsedTimeAlias(t *testing.T) {
	csv := "client_id,client_first_used_time\nabc,2024-02-03T04:05:06Z\n"
	records, err := parseReader(strings.NewReader(csv), "t.csv")
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].ClientFirstUsageTime; got != "2024-02-03T04:05:06Z" {
		t.Errorf("ClientFirstUsageTime = %q, want 2024-02-03T04:05:06Z", got)
	}
}

func TestParseReader_ClientFirstUsedTimeFirstColumnWins(t *testing.T) {
	for _, tc := range []struct{ name, header, row, want string }{
		{"used_first", "client_id,client_first_used_time,client_first_usage_time", "abc,USED,USAGE", "USED"},
		{"usage_first", "client_id,client_first_usage_time,client_first_used_time", "abc,USAGE,USED", "USAGE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, err := parseReader(strings.NewReader(tc.header+"\n"+tc.row+"\n"), "t.csv")
			if err != nil {
				t.Fatal(err)
			}
			if got := records[0].ClientFirstUsageTime; got != tc.want {
				t.Errorf("ClientFirstUsageTime = %q, want %q", got, tc.want)
			}
		})
	}
}
