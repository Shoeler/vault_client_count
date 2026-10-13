package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/golden from current CLI output")

// goldenDiff returns the first few differing lines between want and got.
func goldenDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	shown := 0
	for i := 0; i < len(w) || i < len(g); i++ {
		var wl, gl string
		wok, gok := i < len(w), i < len(g)
		if wok {
			wl = w[i]
		}
		if gok {
			gl = g[i]
		}
		if wok && gok && wl == gl {
			continue
		}
		fmt.Fprintf(&b, "line %d:\n", i+1)
		if wok {
			fmt.Fprintf(&b, "  - %s\n", wl)
		}
		if gok {
			fmt.Fprintf(&b, "  + %s\n", gl)
		}
		if shown++; shown >= 10 {
			b.WriteString("  ... (further differences omitted)\n")
			break
		}
	}
	return b.String()
}

// goldenCombos are the flag sets every fixture run is checked with.
var goldenCombos = []struct {
	name string
	args []string
}{
	{"base", nil},
	{"p", []string{"-p"}},
	{"d", []string{"-d"}},
	{"d_p", []string{"-d", "-p"}},
}

type goldenRun struct {
	label string
	files []string
}

// goldenRuns is one run per fixture plus one over all of them.
func goldenRuns(names []string) []goldenRun {
	runs := []goldenRun{}
	for _, n := range names {
		runs = append(runs, goldenRun{strings.TrimSuffix(n, ".csv"), []string{n}})
	}
	if len(names) > 0 {
		runs = append(runs, goldenRun{"combined", names})
	}
	return runs
}

// prepareGoldens returns the sorted base names of testdata/*.sanitized.csv.
// With no fixtures it skips the test before looking at the goldens, so a
// checkout without the fixtures neither fails on the goldens nor, with
// -update, deletes them. Otherwise it checks testdata/golden for stale files.
func prepareGoldens(t *testing.T, testdata string, update bool) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(testdata, "*.sanitized.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Skip("no testdata/*.sanitized.csv fixtures present; skipping golden tests")
	}
	sort.Strings(matches)
	var names []string
	for _, m := range matches {
		names = append(names, filepath.Base(m))
	}
	expected := map[string]bool{}
	for _, c := range goldenCombos {
		for _, r := range goldenRuns(names) {
			expected[r.label+"."+c.name+".txt"] = true
		}
	}
	checkStaleGoldens(t, filepath.Join(testdata, "golden"), expected, update)
	return names
}

// TestGoldenCounts pins the CLI's stdout (including client counts) on the
// pseudonymized fixtures in testdata/*.sanitized.csv. The CLI runs with
// testdata/ as its working directory.
func TestGoldenCounts(t *testing.T) {
	testdata, err := filepath.Abs("../../testdata")
	if err != nil {
		t.Fatal(err)
	}
	names := prepareGoldens(t, testdata, *update)
	runs := goldenRuns(names)
	goldenDir := filepath.Join(testdata, "golden")
	for _, c := range goldenCombos {
		c := c
		t.Run(c.name, func(t *testing.T) {
			for _, r := range runs {
				r := r
				t.Run(r.label, func(t *testing.T) {
					args := append([]string{}, c.args...)
					for _, f := range r.files {
						args = append(args, "-f", f)
					}
					stdout, stderr, code := runCLI(t, testdata, args...)
					if code != 0 {
						t.Fatalf("exit code %d, want 0\nstderr:\n%s", code, stderr)
					}
					for _, l := range strings.Split(stderr, "\n") {
						if strings.HasPrefix(l, "Error") {
							t.Errorf("stderr has error line: %q", l)
						}
					}
					golden := filepath.Join(goldenDir, r.label+"."+c.name+".txt")
					if *update {
						if err := os.MkdirAll(goldenDir, 0o755); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(golden, []byte(stdout), 0o644); err != nil {
							t.Fatal(err)
						}
						return
					}
					want, err := os.ReadFile(golden)
					if os.IsNotExist(err) {
						t.Fatalf("missing golden file %s; run: go test ./cmd/vault-csv-normalizer -run TestGoldenCounts -update", golden)
					} else if err != nil {
						t.Fatal(err)
					}
					if string(want) != stdout {
						t.Fatalf("output differs from golden %s\n%s\nIf this change is intended, run: go test ./cmd/vault-csv-normalizer -run TestGoldenCounts -update",
							golden, goldenDiff(string(want), stdout))
					}
				})
			}
		})
	}
}

// staleGoldens returns the sorted *.txt names in goldenDir that are not in
// expected. Other files and directories are ignored. A missing goldenDir has
// none.
func staleGoldens(goldenDir string, expected map[string]bool) ([]string, error) {
	entries, err := os.ReadDir(goldenDir)
	if os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var stale []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") && !expected[e.Name()] {
			stale = append(stale, e.Name())
		}
	}
	return stale, nil
}

// checkStaleGoldens fails the test when testdata/golden holds a *.txt file
// that no current fixture run produces, for example after the fixtures were
// renamed by re-running the sanitizer. With update it deletes those files
// instead. Other files and directories are never reported or deleted.
func checkStaleGoldens(t *testing.T, goldenDir string, expected map[string]bool, update bool) {
	t.Helper()
	stale, err := staleGoldens(goldenDir, expected)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) == 0 {
		return
	}
	if update {
		for _, n := range stale {
			if err := os.Remove(filepath.Join(goldenDir, n)); err != nil {
				t.Fatal(err)
			}
			t.Logf("removed stale golden %s", n)
		}
		return
	}
	t.Fatalf("stale golden *.txt file(s) in %s with no matching testdata/*.sanitized.csv fixture "+
		"(were the fixtures renamed or removed?):\n  %s\n"+
		"After confirming the fixture change is intended, delete them or run: "+
		"go test ./cmd/vault-csv-normalizer -run TestGoldenCounts -update",
		goldenDir, strings.Join(stale, "\n  "))
}
