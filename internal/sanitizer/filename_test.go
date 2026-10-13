package sanitizer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Output file name pseudonyms. The known-answer values are shared with
// FilenameTests in scripts/test_sanitize_csv.py so the two ports stay in step.

func writeSaltFile(t *testing.T, dir string, salt []byte) string {
	t.Helper()
	p := filepath.Join(dir, "salt.hex")
	if err := os.WriteFile(p, []byte(hex.EncodeToString(salt)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func readMapping(t *testing.T, path string) [][]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func filenameRows(rows [][]string) [][]string {
	var out [][]string
	for _, r := range rows {
		if r[0] == "filename" {
			out = append(out, r)
		}
	}
	return out
}

func TestFilenamePseudonym(t *testing.T) {
	s, err := New(saltA(), false)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, saltA())
	mac.Write([]byte("filename\x00acme-export"))
	want := "export-" + hex.EncodeToString(mac.Sum(nil))[:12]
	if got := s.Filename("acme-export"); got != want {
		t.Errorf("Filename(acme-export) = %q, want %q", got, want)
	}
	if want != "export-9e4ebd54df0c" {
		t.Errorf("known-answer drift: %q", want)
	}
	if got := s.Filename("Acme-Export"); got != "export-25d317be975f" {
		t.Errorf("Filename(Acme-Export) = %q, want case-sensitive export-25d317be975f", got)
	}
	sb, _ := New(saltB(), false)
	if sb.Filename("acme-export") == want {
		t.Error("filename pseudonym does not depend on the salt")
	}
	// File names never enter the leak-check state.
	if len(s.originalWholes) != 0 || len(s.originalTokens) != 0 || len(s.cache) != 0 {
		t.Error("Filename changed the pseudonym cache or leak-check state")
	}
}

func TestCLIDerivedFilenamesArePseudonymized(t *testing.T) {
	f := newFixture(t)
	salt := writeSaltFile(t, f.dir, saltA())
	a := filepath.Join(f.dir, "acme-export.csv")
	b := filepath.Join(f.dir, "x.CSV")
	writeCSV(t, a, testHeader, testRows)
	writeCSV(t, b, testHeader, testRows)
	out := filepath.Join(f.dir, "out")
	keep := filepath.Join(f.dir, "keep")
	mapping := filepath.Join(f.dir, "map.csv")
	var errBuf bytes.Buffer
	if rc := Main([]string{a, b, "-o", out, "--salt-file", salt, "--mapping-out", mapping}, &errBuf); rc != 0 {
		t.Fatalf("rc = %d; stderr: %s", rc, errBuf.String())
	}
	want := []string{"export-9e4ebd54df0c.sanitized.csv", "export-daa4318cd009.sanitized.csv"}
	if got := listDir(t, out); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("outputs = %v, want %v", got, want)
	}
	// Progress line format is unchanged, now naming the pseudonymous file.
	if !strings.Contains(errBuf.String(), a+" -> "+filepath.Join(out, want[0])+": 11 data rows") {
		t.Errorf("progress line missing; stderr: %s", errBuf.String())
	}

	// Content is identical to a --keep-filenames run with the same salt.
	if rc := Main([]string{a, b, "-o", keep, "--salt-file", salt, "--keep-filenames"}, &errBuf); rc != 0 {
		t.Fatalf("keep rc = %d; stderr: %s", rc, errBuf.String())
	}
	for i, k := range []string{"acme-export.sanitized.csv", "x.sanitized.csv"} {
		p1, _ := os.ReadFile(filepath.Join(out, want[i]))
		p2, _ := os.ReadFile(filepath.Join(keep, k))
		if !bytes.Equal(p1, p2) {
			t.Errorf("%s content differs from %s", want[i], k)
		}
	}

	// One mapping row per renamed file, category "filename", original = stem.
	got := filenameRows(readMapping(t, mapping))
	wantRows := [][]string{
		{"filename", "acme-export", "export-9e4ebd54df0c"},
		{"filename", "x", "export-daa4318cd009"},
	}
	if len(got) != len(wantRows) {
		t.Fatalf("filename mapping rows = %v, want %v", got, wantRows)
	}
	for i := range got {
		if strings.Join(got[i], ",") != strings.Join(wantRows[i], ",") {
			t.Errorf("mapping row %d = %v, want %v", i, got[i], wantRows[i])
		}
	}
}

func TestCLISingleInputToDirectoryIsPseudonymized(t *testing.T) {
	f := newFixture(t)
	salt := writeSaltFile(t, f.dir, saltA())
	src := filepath.Join(f.dir, "acme-export.csv")
	writeCSV(t, src, testHeader, testRows)
	out := filepath.Join(f.dir, "out")
	var errBuf bytes.Buffer
	if rc := Main([]string{src, "-o", out + string(os.PathSeparator), "--salt-file", salt}, &errBuf); rc != 0 {
		t.Fatalf("rc = %d; stderr: %s", rc, errBuf.String())
	}
	if got := listDir(t, out); len(got) != 1 || got[0] != "export-9e4ebd54df0c.sanitized.csv" {
		t.Errorf("outputs = %v", got)
	}
}

func TestCLIExplicitOutputFileNameKept(t *testing.T) {
	f := newFixture(t)
	salt := writeSaltFile(t, f.dir, saltA())
	src := filepath.Join(f.dir, "acme-export.csv")
	writeCSV(t, src, testHeader, testRows)
	dst := filepath.Join(f.dir, "my-choice.csv")
	mapping := filepath.Join(f.dir, "map.csv")
	var errBuf bytes.Buffer
	if rc := Main([]string{src, "-o", dst, "--salt-file", salt, "--mapping-out", mapping}, &errBuf); rc != 0 {
		t.Fatalf("rc = %d; stderr: %s", rc, errBuf.String())
	}
	if _, err := os.Stat(dst); err != nil {
		t.Error(err)
	}
	if rows := filenameRows(readMapping(t, mapping)); len(rows) != 0 {
		t.Errorf("explicit -o file produced filename mapping rows: %v", rows)
	}
}

func TestCLIKeepFilenames(t *testing.T) {
	f := newFixture(t)
	salt := writeSaltFile(t, f.dir, saltA())
	a := filepath.Join(f.dir, "acme-export.csv")
	b := filepath.Join(f.dir, "x.CSV")
	writeCSV(t, a, testHeader, testRows)
	writeCSV(t, b, testHeader, testRows)
	out := filepath.Join(f.dir, "out")
	mapping := filepath.Join(f.dir, "map.csv")
	var errBuf bytes.Buffer
	if rc := Main([]string{a, b, "-o", out, "--salt-file", salt, "--keep-filenames", "--mapping-out", mapping}, &errBuf); rc != 0 {
		t.Fatalf("rc = %d; stderr: %s", rc, errBuf.String())
	}
	want := []string{"acme-export.sanitized.csv", "x.sanitized.csv"}
	if got := listDir(t, out); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("outputs = %v, want %v", got, want)
	}
	if rows := filenameRows(readMapping(t, mapping)); len(rows) != 0 {
		t.Errorf("--keep-filenames produced filename mapping rows: %v", rows)
	}
}

func TestCLIOutputNameCollision(t *testing.T) {
	for _, extra := range [][]string{nil, {"--keep-filenames"}} {
		f := newFixture(t)
		a := filepath.Join(f.dir, "a", "same.csv")
		b := filepath.Join(f.dir, "b", "same.csv")
		for _, p := range []string{a, b} {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			writeCSV(t, p, testHeader, testRows)
		}
		out := filepath.Join(f.dir, "out")
		saved := filepath.Join(f.dir, "saved.salt")
		mapping := filepath.Join(f.dir, "map.csv")
		var errBuf bytes.Buffer
		args := append([]string{a, b, "-o", out, "--save-salt", saved, "--mapping-out", mapping}, extra...)
		if rc := Main(args, &errBuf); rc != 1 {
			t.Errorf("%v: rc = %d, want 1", extra, rc)
		}
		msg := errBuf.String()
		if !strings.Contains(msg, a) || !strings.Contains(msg, b) {
			t.Errorf("%v: error does not name both inputs: %s", extra, msg)
		}
		for _, p := range []string{out, saved, mapping} {
			if _, err := os.Stat(p); err == nil {
				t.Errorf("%v: %s was written despite the collision", extra, p)
			}
		}
	}
}
