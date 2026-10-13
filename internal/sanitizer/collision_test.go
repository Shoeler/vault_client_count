package sanitizer

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Write-target collision checks, salt validation and CLI exit codes. Mirrors
// CollisionTests in scripts/test_sanitize_csv.py so the two ports stay in step.

// fsIsCaseInsensitive reports whether dir's filesystem folds case, using a
// probe file independent of the code under test.
func fsIsCaseInsensitive(t *testing.T, dir string) bool {
	t.Helper()
	p := filepath.Join(dir, "CaseProbe")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p)
	_, err := os.Stat(filepath.Join(dir, "caseprobe"))
	return err == nil
}

// assertRejected runs Main, expects exit code 1 and an error naming every
// string in mention, and checks that none of absent exists afterwards.
func assertRejected(t *testing.T, args []string, mention []string, absent []string) {
	t.Helper()
	var errBuf bytes.Buffer
	if rc := Main(args, &errBuf); rc != 1 {
		t.Errorf("%v: rc = %d, want 1; stderr: %s", args, rc, errBuf.String())
	}
	msg := errBuf.String()
	if !strings.Contains(msg, "error: ") {
		t.Errorf("%v: no error line: %s", args, msg)
	}
	for _, m := range mention {
		if !strings.Contains(msg, m) {
			t.Errorf("%v: error does not name %s: %s", args, m, msg)
		}
	}
	for _, p := range absent {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%v: %s was written despite the error", args, p)
		}
	}
}

func readFileT(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCLIMappingOutEqualsInput(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.dir, "jan.csv")
	writeCSV(t, src, testHeader, testRows)
	before := readFileT(t, src)
	out := filepath.Join(f.dir, "out")
	saved := filepath.Join(f.dir, "saved.salt")
	assertRejected(t, []string{src, "-o", out + string(os.PathSeparator), "--save-salt", saved, "--mapping-out", src},
		[]string{"--mapping-out", src, "input"}, []string{out, saved})
	if !bytes.Equal(readFileT(t, src), before) {
		t.Error("input was modified")
	}
}

func TestCLIMappingOutEqualsOutput(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.dir, "jan.csv")
	writeCSV(t, src, testHeader, testRows)
	shared := filepath.Join(f.dir, "shared.csv")
	saved := filepath.Join(f.dir, "saved.salt")
	assertRejected(t, []string{src, "-o", shared, "--save-salt", saved, "--mapping-out", shared},
		[]string{"--mapping-out", shared, "output"}, []string{shared, saved})

	// Derived output name inside a directory, reached by a different spelling.
	out := filepath.Join(f.dir, "out")
	salt := writeSaltFile(t, f.dir, saltA())
	derived := filepath.Join(out, "export-9e4ebd54df0c.sanitized.csv")
	src2 := filepath.Join(f.dir, "acme-export.csv")
	writeCSV(t, src2, testHeader, testRows)
	sep := string(os.PathSeparator)
	alias := out + sep + "." + sep + "export-9e4ebd54df0c.sanitized.csv"
	assertRejected(t, []string{src2, "-o", out + string(os.PathSeparator), "--salt-file", salt, "--mapping-out", alias},
		[]string{"--mapping-out", derived}, []string{out})
}

func TestCLISaveSaltEqualsInput(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.dir, "jan.csv")
	writeCSV(t, src, testHeader, testRows)
	before := readFileT(t, src)
	out := filepath.Join(f.dir, "out")
	mapping := filepath.Join(f.dir, "jan.mapping.csv")
	assertRejected(t, []string{src, "-o", out + string(os.PathSeparator), "--save-salt", src, "--mapping-out", mapping},
		[]string{"--save-salt", src, "input"}, []string{out, mapping})
	if !bytes.Equal(readFileT(t, src), before) {
		t.Error("input was overwritten by --save-salt")
	}
}

func TestCLIMappingOutEqualsSaveSalt(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.dir, "jan.csv")
	writeCSV(t, src, testHeader, testRows)
	out := filepath.Join(f.dir, "out")
	both := filepath.Join(f.dir, "both.salt")
	assertRejected(t, []string{src, "-o", out + string(os.PathSeparator), "--save-salt", both, "--mapping-out", both},
		[]string{"--save-salt " + both, "--mapping-out " + both}, []string{out, both})
}

func TestCLICaseOnlyCollision(t *testing.T) {
	f := newFixture(t)
	if !fsIsCaseInsensitive(t, f.dir) {
		t.Skip("filesystem is case-sensitive")
	}
	src := filepath.Join(f.dir, "jan.csv")
	writeCSV(t, src, testHeader, testRows)
	before := readFileT(t, src)
	saved := filepath.Join(f.dir, "saved.salt")

	// Output differs from the input only by case.
	upper := filepath.Join(f.dir, "JAN.csv")
	assertRejected(t, []string{src, "-o", upper, "--save-salt", saved},
		[]string{upper, "input"}, []string{saved})
	if !bytes.Equal(readFileT(t, src), before) {
		t.Error("input was overwritten")
	}

	// Two inputs whose kept names differ only by case.
	a := filepath.Join(f.dir, "a", "Jan.csv")
	b := filepath.Join(f.dir, "b", "jan.csv")
	for _, p := range []string{a, b} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		writeCSV(t, p, testHeader, testRows)
	}
	out := filepath.Join(f.dir, "out")
	assertRejected(t, []string{a, b, "-o", out, "--keep-filenames", "--save-salt", saved},
		[]string{a, b}, []string{out, saved})

	// Mapping file and explicit output, neither existing, differ only by case.
	x := filepath.Join(f.dir, "x.csv")
	assertRejected(t, []string{src, "-o", x, "--save-salt", saved, "--mapping-out", filepath.Join(f.dir, "X.csv")},
		[]string{"--mapping-out", x}, []string{x, saved})
}

func TestCaseInsensitiveFSProbeAgreesWithOS(t *testing.T) {
	dir := t.TempDir()
	r := realpath(dir)
	if got, want := caseInsensitiveFS(filepath.Join(r, "missing", "file.csv")), fsIsCaseInsensitive(t, dir); got != want {
		t.Errorf("caseInsensitiveFS = %v, probe file says %v", got, want)
	}
}

func TestLoadSaltEdgeCases(t *testing.T) {
	dir := t.TempDir()
	want16 := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	cases := []struct {
		name    string
		content string
		want    []byte // nil: rejected
	}{
		{"short hex", "00112233445566778899aabbccddee\n", nil},
		{"short raw", "not-hex-short\n", nil},
		{"raw 16+ non-hex", "this is not hex at all!\n", []byte("this is not hex at all!")},
		{"whitespace between hex pairs", "0011 2233\t4455 6677\n8899 aabb ccdd eeff\n", want16},
		{"whitespace splitting a pair is raw", "001 122334455667788 99aabbccddeeff", []byte("001 122334455667788 99aabbccddeeff")},
		{"odd-length hex is raw", "00112233445566778899aabbccddeeff0", []byte("00112233445566778899aabbccddeeff0")},
		{"uppercase hex", "  00112233445566778899AABBCCDDEEFF  \n", want16},
		{"non-ascii raw", "sälzchen-sälzchen", []byte("sälzchen-sälzchen")},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "salt"+string(rune('a'+i)))
		if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		var errBuf bytes.Buffer
		got, err := loadSalt(p, &errBuf)
		if c.want == nil {
			if err == nil || !strings.Contains(err.Error(), "at least 16 bytes") {
				t.Errorf("%s: err = %v, want at-least-16-bytes error", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: salt = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCLIShortSaltRejected(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.dir, "jan.csv")
	writeCSV(t, src, testHeader, testRows)
	salt := filepath.Join(f.dir, "short.salt")
	if err := os.WriteFile(salt, []byte(hex.EncodeToString(make([]byte, 8))), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.dir, "out")
	assertRejected(t, []string{src, "-o", out + string(os.PathSeparator), "--salt-file", salt},
		[]string{salt, "at least 16 bytes"}, []string{out})
}

func TestCLISaveSaltWithSaltFile(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.dir, "jan.csv")
	writeCSV(t, src, testHeader, testRows)
	salt := writeSaltFile(t, f.dir, saltA())
	saved := filepath.Join(f.dir, "saved.salt")
	out := filepath.Join(f.dir, "out")
	assertRejected(t, []string{src, "-o", out + string(os.PathSeparator), "--salt-file", salt, "--save-salt", saved},
		[]string{"--save-salt is only valid"}, []string{out, saved})
}

func TestCLIMissingRequiredArgsExit2(t *testing.T) {
	f := newFixture(t)
	src := filepath.Join(f.dir, "jan.csv")
	writeCSV(t, src, testHeader, testRows)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{src}, "required: -o/--output"},
		{[]string{"-o", filepath.Join(f.dir, "out")}, "required: INPUT.csv"},
		{[]string{}, "required: INPUT.csv, -o/--output"},
		{[]string{src, "--no-such-flag", "-o", filepath.Join(f.dir, "out")}, "no-such-flag"},
	} {
		var errBuf bytes.Buffer
		if rc := Main(c.args, &errBuf); rc != 2 {
			t.Errorf("%v: rc = %d, want 2", c.args, rc)
		}
		if !strings.Contains(errBuf.String(), c.want) {
			t.Errorf("%v: stderr lacks %q: %s", c.args, c.want, errBuf.String())
		}
	}
	if _, err := os.Stat(filepath.Join(f.dir, "out")); err == nil {
		t.Error("out was created on a usage error")
	}
}
