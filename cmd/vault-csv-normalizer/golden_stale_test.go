package main

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// Stale-golden detection and the no-fixture skip, on temp directories so the
// real testdata/golden is never touched.

func writeGoldenFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func dirNames(t *testing.T, dir string) []string {
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

func TestStaleGoldensOnlyTxt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "golden")
	writeGoldenFiles(t, dir, "keep.base.txt", "old.base.txt", "README.md", ".DS_Store", "notes.txt.bak")
	if err := os.Mkdir(filepath.Join(dir, "sub.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := staleGoldens(dir, map[string]bool{"keep.base.txt": true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"old.base.txt"}; !reflect.DeepEqual(got, want) {
		t.Errorf("stale = %v, want %v", got, want)
	}
	if got, err := staleGoldens(filepath.Join(dir, "missing"), nil); err != nil || got != nil {
		t.Errorf("missing dir: stale = %v, err = %v; want none", got, err)
	}
}

func TestCheckStaleGoldensUpdateRemovesOnlyStaleTxt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "golden")
	writeGoldenFiles(t, dir, "keep.base.txt", "old.base.txt", "old.p.txt", "README.md")
	checkStaleGoldens(t, dir, map[string]bool{"keep.base.txt": true}, true)
	if got, want := dirNames(t, dir), []string{"README.md", "keep.base.txt"}; !reflect.DeepEqual(got, want) {
		t.Errorf("after update: %v, want %v", got, want)
	}
}

func TestCheckStaleGoldensNothingStale(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "golden")
	writeGoldenFiles(t, dir, "keep.base.txt", "README.md")
	// Would t.Fatal if anything were reported stale.
	checkStaleGoldens(t, dir, map[string]bool{"keep.base.txt": true}, false)
	if got := dirNames(t, dir); len(got) != 2 {
		t.Errorf("files changed: %v", got)
	}
}

func TestPrepareGoldensNoFixturesSkipsWithoutDeleting(t *testing.T) {
	testdata := t.TempDir()
	golden := filepath.Join(testdata, "golden")
	writeGoldenFiles(t, golden, "acme-export.sanitized.base.txt", "combined.base.txt")
	for _, update := range []bool{false, true} {
		var inner *testing.T
		name := "check"
		if update {
			name = "update"
		}
		t.Run(name, func(t *testing.T) {
			inner = t
			prepareGoldens(t, testdata, update)
			t.Error("prepareGoldens returned instead of skipping")
		})
		if !inner.Skipped() {
			t.Errorf("update=%v: not skipped", update)
		}
		if got := dirNames(t, golden); len(got) != 2 {
			t.Errorf("update=%v: goldens changed: %v", update, got)
		}
	}
}

func TestPrepareGoldensWithFixtures(t *testing.T) {
	testdata := t.TempDir()
	writeGoldenFiles(t, testdata, "a.sanitized.csv", "b.sanitized.csv", "other.csv")
	golden := filepath.Join(testdata, "golden")
	var want []string
	for _, r := range []string{"a.sanitized", "b.sanitized", "combined"} {
		for _, c := range goldenCombos {
			want = append(want, r+"."+c.name+".txt")
		}
	}
	writeGoldenFiles(t, golden, append([]string{"gone.sanitized.base.txt", "README.md"}, want...)...)
	names := prepareGoldens(t, testdata, true)
	if w := []string{"a.sanitized.csv", "b.sanitized.csv"}; !reflect.DeepEqual(names, w) {
		t.Errorf("names = %v, want %v", names, w)
	}
	want = append(want, "README.md")
	sort.Strings(want)
	if got := dirNames(t, golden); !reflect.DeepEqual(got, want) {
		t.Errorf("goldens = %v, want %v", got, want)
	}
}
