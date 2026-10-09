package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeFiles creates empty files with the given names under dir.
func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", path, err)
		}
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

func assertFiles(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual([]string(got), want) {
		t.Errorf("files:\n  got  %q\n  want %q", got, want)
	}
}

func TestExpandInputFiles_LiteralPathsPassThrough(t *testing.T) {
	// Literal paths are not checked for existence here; the parser reports
	// a missing file with its usual error.
	got, err := expandInputFiles([]string{"jan.csv", "missing.csv"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, got, "jan.csv", "missing.csv")
}

func TestExpandInputFiles_WildcardExpandsSorted(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "mar.csv", "jan.csv", "feb.csv", "notes.txt")

	got, err := expandInputFiles([]string{filepath.Join(dir, "*.csv")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, got,
		filepath.Join(dir, "feb.csv"),
		filepath.Join(dir, "jan.csv"),
		filepath.Join(dir, "mar.csv"),
	)
}

func TestExpandInputFiles_QuestionMarkAndClass(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "export-1.csv", "export-2.csv", "export-3.csv", "export-10.csv")

	got, err := expandInputFiles([]string{filepath.Join(dir, "export-?.csv")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, got,
		filepath.Join(dir, "export-1.csv"),
		filepath.Join(dir, "export-2.csv"),
		filepath.Join(dir, "export-3.csv"),
	)

	got, err = expandInputFiles([]string{filepath.Join(dir, "export-[12].csv")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, got,
		filepath.Join(dir, "export-1.csv"),
		filepath.Join(dir, "export-2.csv"),
	)
}

func TestExpandInputFiles_PatternOrderPreserved(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "2023-12.csv", "2024-01.csv", "2024-02.csv")

	got, err := expandInputFiles([]string{
		filepath.Join(dir, "2024-*.csv"),
		filepath.Join(dir, "2023-*.csv"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, got,
		filepath.Join(dir, "2024-01.csv"),
		filepath.Join(dir, "2024-02.csv"),
		filepath.Join(dir, "2023-12.csv"),
	)
}

func TestExpandInputFiles_OverlappingPatternsReadFileOnce(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "jan.csv", "feb.csv")

	got, err := expandInputFiles([]string{
		filepath.Join(dir, "jan.csv"),
		filepath.Join(dir, "*.csv"),
		filepath.Join(dir, ".", "jan.csv"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, got,
		filepath.Join(dir, "jan.csv"),
		filepath.Join(dir, "feb.csv"),
	)
}

func TestExpandInputFiles_NoMatchIsError(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "jan.csv")

	_, err := expandInputFiles([]string{filepath.Join(dir, "*.tsv")})
	if err == nil {
		t.Fatal("expected an error for a pattern that matches no files")
	}
	if !strings.Contains(err.Error(), "no files match") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestExpandInputFiles_InvalidPatternIsError(t *testing.T) {
	_, err := expandInputFiles([]string{"export-[.csv"})
	if err == nil {
		t.Fatal("expected an error for a malformed pattern")
	}
	if !strings.Contains(err.Error(), "invalid file pattern") {
		t.Errorf("unexpected error text: %v", err)
	}
}

func TestExpandInputFiles_SkipsDirectories(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "jan.csv", "archive/old.csv")

	got, err := expandInputFiles([]string{filepath.Join(dir, "*")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, got, filepath.Join(dir, "jan.csv"))
}

func TestExpandInputFiles_LiteralNameWithWildcardChars(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, "export[1].csv", "export1.csv")

	// The pattern would match export1.csv, but a file with that exact name wins.
	literal := filepath.Join(dir, "export[1].csv")
	got, err := expandInputFiles([]string{literal})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, got, literal)
}

// newTestFlagSet mirrors the shape of the real flags: a repeatable -f, a string
// flag and a bool flag.
func newTestFlagSet() (*flag.FlagSet, *multiFlag, *string, *bool) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var files multiFlag
	fs.Var(&files, "f", "")
	sortBy := fs.String("sort", "namespace_path", "")
	dedup := fs.Bool("d", false, "")
	return fs, &files, sortBy, dedup
}

func TestCollectPositionalFiles_FlagsAfterFiles(t *testing.T) {
	fs, files, sortBy, dedup := newTestFlagSet()
	if err := fs.Parse([]string{"-f", "jan.csv", "feb.csv", "mar.csv", "--sort", "client_type", "-d"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	positional, err := collectPositionalFiles(fs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, append(*files, positional...), "jan.csv", "feb.csv", "mar.csv")
	if *sortBy != "client_type" {
		t.Errorf("sort: got %q, want %q", *sortBy, "client_type")
	}
	if !*dedup {
		t.Error("expected -d to be set")
	}
}

func TestCollectPositionalFiles_FilesBetweenAndAfterFlags(t *testing.T) {
	fs, files, sortBy, dedup := newTestFlagSet()
	if err := fs.Parse([]string{"-f", "a.csv", "b.csv", "-d", "c.csv", "-f", "d.csv", "e.csv", "--sort", "source"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	positional, err := collectPositionalFiles(fs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// -f values are collected by the flag itself; the rest are positional.
	assertFiles(t, *files, "a.csv", "d.csv")
	assertFiles(t, positional, "b.csv", "c.csv", "e.csv")
	if *sortBy != "source" {
		t.Errorf("sort: got %q, want %q", *sortBy, "source")
	}
	if !*dedup {
		t.Error("expected -d to be set")
	}
}

func TestCollectPositionalFiles_NoPositionals(t *testing.T) {
	fs, files, _, _ := newTestFlagSet()
	if err := fs.Parse([]string{"-f", "jan.csv", "-d"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	positional, err := collectPositionalFiles(fs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, *files, "jan.csv")
	assertFiles(t, positional)
}

func TestCollectPositionalFiles_TerminatorTakesRestAsFiles(t *testing.T) {
	fs, files, _, dedup := newTestFlagSet()
	if err := fs.Parse([]string{"-f", "jan.csv", "feb.csv", "--", "-d", "-odd.csv"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	positional, err := collectPositionalFiles(fs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertFiles(t, append(*files, positional...), "jan.csv", "feb.csv", "-d", "-odd.csv")
	if *dedup {
		t.Error("-d after -- must be treated as a file, not a flag")
	}
}

func TestCollectPositionalFiles_UnknownFlagAfterFilesIsError(t *testing.T) {
	fs, _, _, _ := newTestFlagSet()
	if err := fs.Parse([]string{"-f", "jan.csv", "feb.csv", "--nope"}); err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if _, err := collectPositionalFiles(fs); err == nil {
		t.Fatal("expected an error for an unknown flag after the file list")
	}
}

func TestValidateSinceFileKeys(t *testing.T) {
	files := []string{"exports/jan.csv", "feb.csv"}
	cases := []struct {
		name    string
		keys    []string
		wantErr bool
	}{
		{"no keys", nil, false},
		{"base name", []string{"jan.csv"}, false},
		{"full path", []string{"exports/jan.csv"}, false},
		{"bare file", []string{"feb.csv"}, false},
		{"all match", []string{"jan.csv", "feb.csv"}, false},
		{"typo", []string{"jna.csv"}, true},
		{"one bad of two", []string{"jan.csv", "mar.csv"}, true},
		{"partial path", []string{"exports"}, true},
	}
	for _, c := range cases {
		err := validateSinceFileKeys(c.keys, files)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}

func TestValidateSinceFileKeys_ErrorNamesKey(t *testing.T) {
	err := validateSinceFileKeys([]string{"nope.csv"}, []string{"a.csv"})
	if err == nil || !strings.Contains(err.Error(), `"nope.csv"`) {
		t.Errorf("expected error naming the key, got %v", err)
	}
}

// ==== P-M1 (new) ====
func TestFileDateFlag_Set(t *testing.T) {
	f := make(fileDateFlag)
	for _, v := range []string{"jan.csv=2024-01-15", "odd=name.csv=2024-02-01"} {
		if err := f.Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	for _, bad := range []string{"jan.csv", "=2024-01-15", ""} {
		if err := f.Set(bad); err == nil {
			t.Errorf("Set(%q): expected error", bad)
		}
	}
	want := map[string]string{"jan.csv": "2024-01-15", "odd=name.csv": "2024-02-01"} // split on the last '='
	if !reflect.DeepEqual(map[string]string(f), want) {
		t.Errorf("flag value = %v, want %v", map[string]string(f), want)
	}
	if got := sinceFileKeys(f); !reflect.DeepEqual(got, []string{"jan.csv", "odd=name.csv"}) {
		t.Errorf("sinceFileKeys = %v, want sorted keys", got)
	}
}

// ---- end-to-end CLI tests: re-run this test binary as the CLI ----

const cliArgsEnv = "VCN_CLI_ARGS"

// TestMain lets the test binary act as the CLI when cliArgsEnv is set.
func TestMain(m *testing.M) {
	if args, ok := os.LookupEnv(cliArgsEnv); ok {
		os.Args = append([]string{"vault-csv-normalizer"}, strings.Split(args, "\x1f")...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runCLI runs the CLI in dir with args and returns stdout, stderr and the exit code.
func runCLI(t *testing.T, dir string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), cliArgsEnv+"="+strings.Join(args, "\x1f"))
	cmd.Stdin = nil
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running CLI: %v", err)
	}
	return stdout.String(), stderr.String(), code
}

func writeCSV(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// totalLine returns the "TOTAL: n" line of a summary section, whitespace-collapsed.
func totalLines(out string) []string {
	var got []string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "TOTAL:" {
			got = append(got, f[1])
		}
	}
	return got
}

// ==== P-M2 (new) ====
func TestCLI_PKIPartitionFromFixtures(t *testing.T) {
	root, _ := filepath.Abs("../../testdata")
	stdout, stderr, code := runCLI(t, t.TempDir(), "-f",
		filepath.Join(root, "export-2024-01.csv"), filepath.Join(root, "export-2024-02-legacy.csv"), "-d", "-p")
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	// 13 records; PKI = 1 acme + 2 auth_cert (jan) + 1 acme (feb).
	if got := totalLines(stdout); !reflect.DeepEqual(got, []string{"9", "4"}) {
		t.Errorf("non-PKI/PKI totals = %v, want [9 4]; stdout:\n%s", got, stdout)
	}
}

// ==== P-M3 (new) — CLAUDE.md invariant: dedup first, filter second ====
func TestCLI_FiltersRunAfterDedup(t *testing.T) {
	dir := t.TempDir()
	hdr := "client_id,namespace_path,mount_path,client_type,token_creation_time\n"
	// The same client appears in both files; -d keeps the record with a mount
	// path (finance/). Filtering on education/ afterwards must therefore find
	// nothing. Filtering first would wrongly keep the jan.csv row.
	writeCSV(t, dir, "jan.csv", hdr+"c1,education/,,entity,2024-01-05T00:00:00Z\n")
	writeCSV(t, dir, "feb.csv", hdr+"c1,finance/,auth/ldap/,entity,2024-02-05T00:00:00Z\n")
	stdout, stderr, code := runCLI(t, dir, "-f", "jan.csv", "feb.csv", "-d", "--namespace", "education")
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	if strings.Contains(stdout, "TOTAL:") {
		t.Errorf("expected no records after dedup-then-filter, got:\n%s", stdout)
	}
}

// ==== P-M4 (new) — main.go sorts by token_creation_time before dedup ====
func TestCLI_AliasDedupKeepsEarliestRecordRegardlessOfFileOrder(t *testing.T) {
	dir := t.TempDir()
	hdr := "client_id,mount_type,client_type,token_creation_time,entity_alias_name\n"
	writeCSV(t, dir, "feb.csv", hdr+"c2,ldap,entity,2024-02-10T00:00:00Z,alice\n")
	writeCSV(t, dir, "jan.csv", hdr+"c1,ldap,entity,2024-01-05T00:00:00Z,alice-t0\n")
	out := filepath.Join(dir, "monthly.tsv")
	// feb.csv is listed first; the kept record must still be the January one.
	_, stderr, code := runCLI(t, dir, "-f", "feb.csv", "jan.csv", "--dedup-alias",
		"-monthly-output", out, "-monthly-entitlement", "1")
	if code != 0 {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	want := "date\tentitlement\tcumulative_total\n2024-01-01\t1\t1\n"
	if string(b) != want {
		t.Errorf("monthly output = %q, want %q", string(b), want)
	}
}

// ==== P-M5 (new) ====
func TestCLI_GenerateTFRequiresPerFileDedup(t *testing.T) {
	dir := t.TempDir()
	writeCSV(t, dir, "jan.csv", "client_id\nc1\n")
	_, stderr, code := runCLI(t, dir, "-f", "jan.csv", "--generate-tf")
	if code != 1 || !strings.Contains(stderr, "--generate-tf requires --dedup-methods-per-file") {
		t.Errorf("exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, tfOutputPath)); !os.IsNotExist(err) {
		t.Error("no Terraform file should be written")
	}
}
