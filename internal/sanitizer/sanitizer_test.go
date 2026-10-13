package sanitizer

import (
	"bytes"
	"encoding/csv"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Port of scripts/test_sanitize_csv.py.

func saltA() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func saltB() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// Legacy names (alias_name, namespace, mount, type, timestamp) mixed with
// current names, a BOM, an unknown column, and one short row.
const testHeader = "\xef\xbb\xbfclient_id,entity_name,alias_name,entity_alias_metadata.username," +
	"namespace_id,namespace,mount_accessor,mount,mount_type,type,timestamp,secret_note"

var testRows = []string{
	// 0 LDAP alice
	"c-0001-alice-ldap,alice-entity,alice,,root,[root],auth_ldap_1a2b3c4d,auth/ldap/,ldap,entity,2024-01-05T08:12:34Z,hunter2-note",
	// 1 LDAP alice-t0 (tier suffix)
	"c-0002-alice-t0,alice-entity,alice-t0,,root,[root],auth_ldap_1a2b3c4d,auth/ldap/,ldap,entity,2024-01-06T08:12:34Z,note-two",
	// 2 JWT alice@corp.com
	"c-0003-alice-jwt,,alice@corp.com,,abc12,engineering/,auth_jwt_9f8e7d6c,auth/jwt-corp/,jwt,entity,2024-02-01T00:00:00-05:00,x",
	// 3 LDAP Alice (different case)
	"c-0004-Alice,,Alice,,abc12,engineering/,auth_ldap_1a2b3c4d,auth/ldap/,ldap,entity,2024-02-02T10:00:00Z,x",
	// 4 OIDC with blank alias and metadata username
	"c-0005-oidc-blank,,,alice,def34,engineering/team-a/,auth_oidc_55aa66bb,auth/oidc/,oidc,entity,2024-02-03T10:00:00Z,x",
	// 5 OIDC with UUID subject alias and metadata username
	"c-0006-oidc-sub,,0f8fad5b-d9cb-469f-a165-70867728950e,alice,def34,engineering/team-a/,auth_oidc_55aa66bb,auth/oidc/,oidc,entity,2024-02-03T11:00:00Z,x",
	// 6 abandoned entity: blank entity name and alias, blank mount
	"c-0007-abandoned,,,,root,,,,,entity,2024-03-01T00:00:00Z,x",
	// 7 cert auth (PKI by accessor prefix)
	"c-0008-cert,certbox-entity,certbox.corp.com,,root,[root],auth_cert_77cc88dd,auth/cert/,cert,entity,2024-03-02T00:00:00Z,x",
	// 8 ACME client
	"0f8fad5b-d9cb-469f-a165-70867728950f,,,,root,root,,pki_int/,pki,pki-acme,2024-03-03T00:00:00Z,x",
	// 9 short row (trailing columns missing)
	"c-0010-short,shorty-entity,bob@corp.com,,root,[root],auth_ldap_1a2b3c4d",
	// 10 same client as row 0 (duplicate client id)
	"c-0001-alice-ldap,alice-entity,alice,,root,[root],auth_ldap_1a2b3c4d,auth/ldap/,ldap,entity,2024-01-07T08:12:34Z,x",
}

var originalSecrets = []string{
	"c-0001-alice-ldap", "alice-entity", "alice", "Alice", "corp.com", "abc12",
	"def34", "engineering", "team-a", "1a2b3c4d", "9f8e7d6c", "jwt-corp",
	"0f8fad5b-d9cb-469f-a165-70867728950e", "certbox", "77cc88dd", "pki_int",
	"shorty-entity", "hunter2-note", "c-0010-short",
}

func writeCSV(t *testing.T, path, header string, rows []string) {
	t.Helper()
	data := header + "\n" + strings.Join(rows, "\n") + "\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readCSV(t *testing.T, path string) (string, []string, [][]string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	r := csv.NewReader(strings.NewReader(strings.TrimLeft(text, "\xef\xbb\xbf")))
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return text, recs[0], recs[1:]
}

func idx(t *testing.T, header []string, name string) int {
	t.Helper()
	for i, h := range header {
		if h == name {
			return i
		}
	}
	t.Fatalf("column %q not in header %v", name, header)
	return -1
}

func eq(t *testing.T, got, want interface{}) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

type fixture struct {
	t   *testing.T
	dir string
	log *bytes.Buffer
}

func newFixture(t *testing.T) *fixture {
	return &fixture{t: t, dir: t.TempDir(), log: &bytes.Buffer{}}
}

type runOpts struct {
	salt  []byte
	name  string
	rows  []string
	keep  map[string]bool
	san   *Sanitizer
	round bool
}

func (f *fixture) runOne(o runOpts) (string, []string, [][]string) {
	f.t.Helper()
	if o.salt == nil {
		o.salt = saltA()
	}
	if o.name == "" {
		o.name = "in.csv"
	}
	if o.rows == nil {
		o.rows = testRows
	}
	src := filepath.Join(f.dir, o.name)
	writeCSV(f.t, src, testHeader, o.rows)
	dst := filepath.Join(f.dir, o.name+".out")
	s := o.san
	if s == nil {
		var err error
		if s, err = New(o.salt, o.round); err != nil {
			f.t.Fatal(err)
		}
	}
	if _, err := SanitizeFile(s, src, dst, o.keep, f.log); err != nil {
		f.t.Fatal(err)
	}
	return readCSV(f.t, dst)
}

func TestBOMAndHeaderPreservedUnknownDropped(t *testing.T) {
	f := newFixture(t)
	text, header, rows := f.runOne(runOpts{})
	if !strings.HasPrefix(text, "\xef\xbb\xbf") {
		t.Error("BOM not preserved")
	}
	for _, h := range header {
		if h == "secret_note" {
			t.Error("secret_note not dropped")
		}
	}
	eq(t, header[:3], []string{"client_id", "entity_name", "alias_name"})
	if !strings.Contains(f.log.String(), "secret_note") {
		t.Error("log does not mention secret_note")
	}
	if len(rows) != len(testRows) {
		t.Errorf("rows = %d, want %d", len(rows), len(testRows))
	}
}

func TestKeepColumns(t *testing.T) {
	f := newFixture(t)
	rows := make([]string, len(testRows))
	for i, r := range testRows {
		rows[i] = strings.ReplaceAll(r, "hunter2-note", "zz")
	}
	_, header, _ := f.runOne(runOpts{rows: rows, keep: map[string]bool{"secret_note": true}})
	idx(t, header, "secret_note")
}

func TestAliasRelationships(t *testing.T) {
	f := newFixture(t)
	_, h, rows := f.runOne(runOpts{})
	a := idx(t, h, "alias_name")
	u := idx(t, h, "entity_alias_metadata.username")
	alice, aliceT0, aliceJWT, capAlice := rows[0][a], rows[1][a], rows[2][a], rows[3][a]
	// Tier suffix kept literally; StripTierSuffix(alice-t0) == alice.
	if !strings.HasSuffix(aliceT0, "-t0") {
		t.Errorf("tier suffix lost: %q", aliceT0)
	}
	eq(t, aliceT0[:len(aliceT0)-3], alice)
	// BaseAlias(alice@corp.com) == alice.
	if !strings.Contains(aliceJWT, "@") {
		t.Errorf("no @ in %q", aliceJWT)
	}
	eq(t, strings.SplitN(aliceJWT, "@", 2)[0], alice)
	if strings.Contains(aliceJWT, "corp") {
		t.Errorf("domain leaked: %q", aliceJWT)
	}
	// Case difference preserved.
	if capAlice == alice {
		t.Error("Alice and alice collapsed")
	}
	// Metadata username equals the LDAP alias.
	eq(t, rows[4][u], alice)
	eq(t, rows[5][u], alice)
	// Blank alias stays blank; UUID subject becomes a different UUID.
	eq(t, rows[4][a], "")
	if !uuidRe.MatchString(rows[5][a]) {
		t.Errorf("not a UUID: %q", rows[5][a])
	}
	if rows[5][a] == "0f8fad5b-d9cb-469f-a165-70867728950e" {
		t.Error("UUID alias unchanged")
	}
}

func TestBlanksAndRootFormsPreserved(t *testing.T) {
	f := newFixture(t)
	_, h, rows := f.runOne(runOpts{})
	en, ns, nsid := idx(t, h, "entity_name"), idx(t, h, "namespace"), idx(t, h, "namespace_id")
	mp, ma := idx(t, h, "mount"), idx(t, h, "mount_accessor")
	eq(t, rows[2][en], "")
	eq(t, rows[6][en], "")
	eq(t, rows[6][mp], "")
	eq(t, rows[6][ma], "")
	eq(t, rows[6][ns], "")
	eq(t, rows[0][ns], "[root]")
	eq(t, rows[8][ns], "root")
	eq(t, rows[0][nsid], "root")
	if rows[0][en] == "" {
		t.Error("entity_name blanked")
	}
}

func TestNamespaceHierarchy(t *testing.T) {
	f := newFixture(t)
	_, h, rows := f.runOne(runOpts{})
	ns := idx(t, h, "namespace")
	parent, child := rows[2][ns], rows[4][ns]
	if !strings.HasSuffix(parent, "/") {
		t.Errorf("parent %q lacks trailing slash", parent)
	}
	if !strings.HasPrefix(child, parent) {
		t.Errorf("child %q does not extend parent %q", child, parent)
	}
	if strings.Count(child, "/") != 2 {
		t.Errorf("child %q slash count", child)
	}
	if strings.Contains(child, "engineering") {
		t.Errorf("child %q leaks", child)
	}
}

func TestMountPathAndAccessorStructure(t *testing.T) {
	f := newFixture(t)
	_, h, rows := f.runOne(runOpts{})
	mp, ma := idx(t, h, "mount"), idx(t, h, "mount_accessor")
	eq(t, rows[0][mp], "auth/ldap/")
	if !strings.HasPrefix(rows[2][mp], "auth/mnt-") {
		t.Errorf("mount %q", rows[2][mp])
	}
	if !strings.HasSuffix(rows[8][mp], "/") {
		t.Errorf("mount %q", rows[8][mp])
	}
	if !strings.HasPrefix(rows[7][ma], "auth_cert_") {
		t.Errorf("accessor %q", rows[7][ma])
	}
	if rows[7][ma] == "auth_cert_77cc88dd" {
		t.Error("cert accessor unchanged")
	}
	if !strings.HasPrefix(rows[0][ma], "auth_ldap_") {
		t.Errorf("accessor %q", rows[0][ma])
	}
	eq(t, rows[0][ma], rows[1][ma])
	if rows[0][ma] == rows[4][ma] {
		t.Error("ldap and oidc accessors equal")
	}
}

func TestPassthroughAndClientIDs(t *testing.T) {
	f := newFixture(t)
	_, h, rows := f.runOne(runOpts{})
	cid, ty, mt, ts := idx(t, h, "client_id"), idx(t, h, "type"), idx(t, h, "mount_type"), idx(t, h, "timestamp")
	eq(t, rows[8][ty], "pki-acme")
	eq(t, rows[2][mt], "jwt")
	eq(t, rows[0][ts], "2024-01-05T08:12:34Z")
	eq(t, rows[0][cid], rows[10][cid])
	if rows[0][cid] == rows[1][cid] {
		t.Error("distinct client ids collided")
	}
	if !uuidRe.MatchString(rows[8][cid]) {
		t.Errorf("not a UUID: %q", rows[8][cid])
	}
}

func TestShortRowKeptShort(t *testing.T) {
	f := newFixture(t)
	_, _, rows := f.runOne(runOpts{})
	if len(rows[9]) != 7 {
		t.Errorf("short row has %d fields, want 7", len(rows[9]))
	}
}

func TestRoundTimestamps(t *testing.T) {
	f := newFixture(t)
	_, h, rows := f.runOne(runOpts{round: true})
	ts := idx(t, h, "timestamp")
	eq(t, rows[0][ts], "2024-01-05T00:00:00Z")
	// -05:00 offset: UTC date is 2024-02-01.
	eq(t, rows[2][ts], "2024-02-01T00:00:00Z")
	eq(t, RoundTimestampToDay("2024-01-31T23:30:00-05:00"), "2024-02-01T00:00:00Z")
	eq(t, RoundTimestampToDay("2024-01-05 08:00:00 +0000 UTC"), "2024-01-05 00:00:00 +0000 UTC")
	eq(t, RoundTimestampToDay("1706745600"), "1706745600")
	eq(t, RoundTimestampToDay("2024-01-05"), "2024-01-05")
}

func TestSameSaltConsistentAcrossFiles(t *testing.T) {
	f := newFixture(t)
	s, err := New(saltA(), false)
	if err != nil {
		t.Fatal(err)
	}
	_, _, r1 := f.runOne(runOpts{name: "a.csv", san: s})
	_, _, r2 := f.runOne(runOpts{name: "b.csv", san: s})
	if !sameRows(r1, r2) {
		t.Error("shared sanitizer gave different rows")
	}
	_, _, r3 := f.runOne(runOpts{name: "c.csv", salt: saltA()}) // fresh run, same salt
	if !sameRows(r1, r3) {
		t.Error("fresh sanitizer with same salt gave different rows")
	}
}

func sameRows(a, b [][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if strings.Join(a[i], "\x00") != strings.Join(b[i], "\x00") || len(a[i]) != len(b[i]) {
			return false
		}
	}
	return true
}

func TestDifferentSaltDiffers(t *testing.T) {
	f := newFixture(t)
	_, h, r1 := f.runOne(runOpts{name: "a.csv", salt: saltA()})
	_, _, r2 := f.runOne(runOpts{name: "b.csv", salt: saltB()})
	cid := idx(t, h, "client_id")
	if r1[0][cid] == r2[0][cid] {
		t.Error("client_id equal under different salts")
	}
	al := idx(t, h, "alias_name")
	if r1[0][al] == r2[0][al] {
		t.Error("alias equal under different salts")
	}
}

func TestNoOriginalValueRemains(t *testing.T) {
	f := newFixture(t)
	text, _, _ := f.runOne(runOpts{})
	body := strings.SplitN(text, "\n", 2)[1]
	for _, secret := range originalSecrets {
		if strings.Contains(body, secret) {
			t.Errorf("original value %q remains", secret)
		}
	}
}

func TestLeakCheckFailsAndRemovesOutput(t *testing.T) {
	f := newFixture(t)
	rows := make([]string, len(testRows))
	for i, r := range testRows {
		rows[i] = strings.ReplaceAll(r, ",hunter2-note", ",alice-entity")
	}
	src := filepath.Join(f.dir, "leak.csv")
	writeCSV(t, src, testHeader, rows)
	dst := filepath.Join(f.dir, "leak.out")
	s, err := New(saltA(), false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = SanitizeFile(s, src, dst, map[string]bool{"secret_note": true}, f.log)
	var se *SanitizeError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want SanitizeError", err)
	}
	if strings.Contains(err.Error(), "alice-entity") {
		t.Error("error message prints the leaked value")
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Error("output file exists after failed leak check")
	}
	entries, _ := os.ReadDir(f.dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".sanitize-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestMissingClientIDRejected(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.dir, "bad.csv")
	writeCSV(t, src, "foo,bar", []string{"1,2"})
	s, err := New(saltA(), false)
	if err != nil {
		t.Fatal(err)
	}
	_, err = SanitizeFile(s, src, src+".out", map[string]bool{}, f.log)
	var se *SanitizeError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want SanitizeError", err)
	}
}

func TestCLI(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.dir, "x.csv")
	writeCSV(t, src, testHeader, testRows)
	out := filepath.Join(f.dir, "out")
	salt := filepath.Join(f.dir, "salt")
	mapping := filepath.Join(f.dir, "map.csv")
	var errBuf bytes.Buffer
	rc := Main([]string{src, "-o", out + string(os.PathSeparator), "--save-salt", salt, "--mapping-out", mapping, "--keep-filenames"}, &errBuf)
	rc2 := Main([]string{filepath.Join(f.dir, "missing.csv"), "-o", out}, &errBuf)
	if rc != 0 {
		t.Errorf("rc = %d, want 0; stderr: %s", rc, errBuf.String())
	}
	if rc2 == 0 {
		t.Error("rc2 = 0, want non-zero")
	}
	if _, err := os.Stat(filepath.Join(out, "x.sanitized.csv")); err != nil {
		t.Error(err)
	}
	for _, p := range []string{salt, mapping} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, st.Mode().Perm())
		}
	}
	if !strings.Contains(errBuf.String(), "WARNING") {
		t.Error("stderr lacks WARNING")
	}
}
