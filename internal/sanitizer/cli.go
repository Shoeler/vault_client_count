package sanitizer

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const usageText = `usage: sanitize-csv [options] INPUT.csv [INPUT.csv ...] -o OUTPUT

Sanitize Vault client-activity export CSVs for sharing.

Identifiers (client_id, entity_name, alias names, metadata usernames,
namespace paths/IDs, mount paths, mount accessors) are replaced with
keyed HMAC-SHA256 pseudonyms. Equality, blankness, alias '@' domain
splits, -t0/-t1/-t2 tier suffixes, the auth_cert accessor prefix, root
namespace forms and well-known mount type names are preserved, so
vault-csv-normalizer reports the same counts, dedup results, PKI
partition, abandoned-client counts and monthly output.

mount_type, auth_method, client_type and timestamps pass through.
Unrecognized columns are dropped unless named in --keep-columns.
Each output is re-scanned for original values before it is kept.
Output file names derived from input names are pseudonymized too
(export-<hex>.sanitized.csv) unless --keep-filenames is given.

options:
`

const usageEpilog = `
examples:
  sanitize-csv export.csv -o export.sanitized.csv
  sanitize-csv jan.csv feb.csv -o out/ --save-salt customer.salt
  sanitize-csv mar.csv -o out/ --salt-file customer.salt
  sanitize-csv jan.csv -o out/ --keep-filenames

Use the same salt for every file from one customer so values map
consistently across files. Keep the salt private: anyone holding the
salt can confirm guesses of original values.
`

// Main runs the sanitize-csv command line and returns the process exit code.
func Main(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("sanitize-csv", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		output, saltFile, saveSalt, mappingOut, keepColumns string
		roundTS, keepNames                                  bool
	)
	fs.StringVar(&output, "o", "", "output directory (files are written as export-<hex>.sanitized.csv,\na keyed pseudonym of the input name), or an output file path\nwhen there is a single input (that name is used as given)")
	fs.StringVar(&output, "output", "", "same as -o")
	fs.StringVar(&saltFile, "salt-file", "", "read the secret salt from `PATH` (hex or raw, at least 16 bytes);\nrequired to map several runs consistently")
	fs.StringVar(&saveSalt, "save-salt", "", "save the generated salt to `PATH` (mode 0600) for later runs")
	fs.StringVar(&mappingOut, "mapping-out", "", "write a reversible original->pseudonym mapping CSV to `PATH`\n(mode 0600). SENSITIVE: it contains every original value")
	fs.StringVar(&keepColumns, "keep-columns", "", "comma-separated unrecognized columns `a,b` to pass through unchanged")
	fs.BoolVar(&keepNames, "keep-filenames", false, "name derived outputs <name>.sanitized.csv after the input file\ninstead of pseudonymizing the name (input names may identify\nthe customer)")
	fs.BoolVar(&roundTS, "round-timestamps-to-day", false, "truncate parseable timestamps to midnight UTC (month buckets are\nunchanged; --since results can shift by up to one day)")
	fs.Usage = func() {
		fmt.Fprint(stderr, usageText)
		fs.PrintDefaults()
		fmt.Fprint(stderr, usageEpilog)
	}

	// Everything after a literal "--" is a file name. Flags may be mixed with
	// the input files, as with the Python script's argparse.
	var inputs []string
	var tail []string
	for i, a := range args {
		if a == "--" {
			args, tail = args[:i], args[i+1:]
			break
		}
	}
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if err == flag.ErrHelp {
				return 0
			}
			return 2
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		inputs = append(inputs, rest[0])
		rest = rest[1:]
	}
	inputs = append(inputs, tail...)
	outputSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "o" || f.Name == "output" {
			outputSet = true
		}
	})
	if len(inputs) == 0 || !outputSet {
		var missing []string
		if len(inputs) == 0 {
			missing = append(missing, "INPUT.csv")
		}
		if !outputSet {
			missing = append(missing, "-o/--output")
		}
		fs.Usage()
		fmt.Fprintf(stderr, "sanitize-csv: error: the following arguments are required: %s\n", strings.Join(missing, ", "))
		return 2
	}

	if err := run(inputs, output, saltFile, saveSalt, mappingOut, keepColumns, roundTS, keepNames, stderr); err != nil {
		fmt.Fprintf(stderr, "error: %s\n", err)
		return 1
	}
	return 0
}

func run(inputs []string, output, saltFile, saveSalt, mappingOut, keepColumns string, roundTS, keepNames bool, stderr io.Writer) error {
	for _, p := range inputs {
		if st, err := os.Stat(p); err != nil || !st.Mode().IsRegular() {
			return errorf("input file not found: %s", p)
		}
	}
	if saltFile != "" && saveSalt != "" {
		return errorf("--save-salt is only valid when the salt is generated (without --salt-file)")
	}
	var salt []byte
	if saltFile != "" {
		var err error
		if salt, err = loadSalt(saltFile, stderr); err != nil {
			return err
		}
	} else {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
	}
	keepExtra := map[string]bool{}
	for _, name := range strings.Split(keepColumns, ",") {
		name = strings.ToLower(pyStrip(name))
		if name == "" {
			continue
		}
		if _, ok := canonicalColumn(name); ok {
			fmt.Fprintf(stderr, "warning: --keep-columns %s ignored: it is a recognized "+
				"column and is always sanitized\n", name)
			continue
		}
		keepExtra[name] = true
	}

	s, err := New(salt, roundTS)
	if err != nil {
		return err
	}
	// Output paths and every check on them come before anything is written.
	outputs, derived := outputPaths(inputs, output, s, keepNames)
	if err := checkCollisions(inputs, outputs, [][2]string{
		{"--save-salt", saveSalt},
		{"--mapping-out", mappingOut},
	}); err != nil {
		return err
	}

	if saltFile == "" {
		if saveSalt != "" {
			if err := writePrivate(saveSalt, []byte(hex.EncodeToString(salt)+"\n")); err != nil {
				return err
			}
			fmt.Fprintf(stderr, "salt saved to %s (mode 0600); keep it secret\n", saveSalt)
		} else if len(inputs) == 1 {
			fmt.Fprint(stderr, "note: a random salt was used; pass --save-salt to sanitize "+
				"other files from this customer consistently later\n")
		}
	}
	if derived {
		if err := os.MkdirAll(output, 0o777); err != nil {
			return err
		}
	}
	for i, in := range inputs {
		if _, err := SanitizeFile(s, in, outputs[i], keepExtra, stderr); err != nil {
			return err
		}
	}

	if mappingOut != "" {
		var buf bytes.Buffer
		bw := bufio.NewWriter(&buf)
		writeRow(bw, []string{"category", "original", "pseudonym"}, "\r\n")
		for _, r := range s.MappingRows() {
			writeRow(bw, []string{r.Category, r.Original, r.Pseudonym}, "\r\n")
		}
		bw.Flush()
		if err := writePrivate(mappingOut, buf.Bytes()); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "WARNING: %s contains every ORIGINAL identifier and reverses the "+
			"sanitization. Treat it as confidential customer data; never share it "+
			"alongside the sanitized files.\n", mappingOut)
	}
	return nil
}

// writePrivate creates or truncates path with mode 0600 and writes data.
func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func isASCIISpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

// fromHex mimics Python's bytes.fromhex on an ASCII string: whitespace is
// skipped between byte pairs; anything else non-hex fails.
func fromHex(data []byte) ([]byte, bool) {
	hexVal := func(c byte) int {
		switch {
		case c >= '0' && c <= '9':
			return int(c - '0')
		case c >= 'a' && c <= 'f':
			return int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			return int(c-'A') + 10
		}
		return -1
	}
	for _, c := range data {
		if c >= 0x80 {
			return nil, false
		}
	}
	out := []byte{}
	for i := 0; i < len(data); {
		if isASCIISpace(data[i]) {
			i++
			continue
		}
		if i+1 >= len(data) {
			return nil, false
		}
		hi, lo := hexVal(data[i]), hexVal(data[i+1])
		if hi < 0 || lo < 0 {
			return nil, false
		}
		out = append(out, byte(hi<<4|lo))
		i += 2
	}
	return out, true
}

func loadSalt(path string, stderr io.Writer) ([]byte, error) {
	st, err := os.Stat(path)
	var data []byte
	if err == nil {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, errorf("cannot read salt file %s: %s", path, err)
	}
	data = bytes.TrimFunc(data, func(r rune) bool { return r < 0x80 && isASCIISpace(byte(r)) })
	if st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(stderr, "warning: salt file %s is readable by group/other; chmod 600 it\n", path)
	}
	salt, ok := fromHex(data)
	if !ok {
		salt = data
	}
	if len(salt) < 16 {
		return nil, errorf("salt file %s must contain at least 16 bytes (32 hex chars)", path)
	}
	return salt, nil
}

// fileStem is the input's base name without a trailing .csv (any case).
func fileStem(p string) string {
	base := filepath.Base(p)
	if strings.HasSuffix(strings.ToLower(base), ".csv") {
		return base[:len(base)-4]
	}
	return base
}

// outputPaths returns the output path for each input, and whether they were
// derived from the input names (out is a directory, or there are several
// inputs) rather than given explicitly as a single output file. Derived names
// are export-<hex>.sanitized.csv (see Sanitizer.Filename), or
// <stem>.sanitized.csv with keepNames. It does not create the directory.
func outputPaths(inputs []string, out string, s *Sanitizer, keepNames bool) ([]string, bool) {
	if st, err := os.Stat(out); len(inputs) == 1 && !(err == nil && st.IsDir()) && !strings.HasSuffix(out, string(os.PathSeparator)) {
		return []string{out}, false
	}
	paths := make([]string, 0, len(inputs))
	for _, p := range inputs {
		stem := fileStem(p)
		if !keepNames {
			stem = s.Filename(stem)
		}
		paths = append(paths, filepath.Join(out, stem+".sanitized.csv"))
	}
	return paths, true
}

// realpath resolves symlinks in the longest existing prefix of p, like
// Python's os.path.realpath, which tolerates a nonexistent final component.
func realpath(p string) string {
	abs := absPath(p)
	cur := abs
	var tail []string
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				r = filepath.Join(r, tail[i])
			}
			return r
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

// Collision checks. Two paths name the same file when their resolved forms
// (realpath) are equal, when both exist and os.SameFile says so (hard links,
// or a case variant of an existing file on a case-insensitive filesystem), or
// when the resolved forms differ only by case and the filesystem holding them
// folds case (macOS and Windows defaults). The last rule covers targets that
// do not exist yet, such as two derived outputs. Case-insensitivity is probed
// read-only: take the deepest existing component of the resolved path whose
// name has an ASCII letter, swap the case of its ASCII letters, and see
// whether that name is the same file. Nothing is created. Case is folded with
// strings.ToLower (str.lower in the Python port). scripts/sanitize_csv.py
// implements the same rules; keep them identical.

func asciiSwapCase(name string) string {
	b := []byte(name)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + ('a' - 'A')
		case c >= 'a' && c <= 'z':
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

// caseInsensitiveFS reports whether the filesystem holding the resolved path
// p folds case.
func caseInsensitiveFS(p string) bool {
	for {
		name, parent := filepath.Base(p), filepath.Dir(p)
		if swapped := asciiSwapCase(name); swapped != name {
			if st, err := os.Stat(p); err == nil {
				st2, err := os.Stat(filepath.Join(parent, swapped))
				return err == nil && os.SameFile(st, st2)
			}
		}
		if parent == p {
			return false
		}
		p = parent
	}
}

// sameFile reports whether paths a and b name the same file (see above).
func sameFile(a, b string) bool {
	ra, rb := realpath(a), realpath(b)
	if ra == rb {
		return true
	}
	if sa, err := os.Stat(ra); err == nil {
		if sb, err := os.Stat(rb); err == nil && os.SameFile(sa, sb) {
			return true
		}
	}
	return strings.ToLower(ra) == strings.ToLower(rb) && caseInsensitiveFS(ra)
}

// checkCollisions rejects any write target that names an input or another
// target. extras holds {flag, path} for --save-salt and --mapping-out; empty
// paths are skipped. It runs before anything is written.
func checkCollisions(inputs, outputs []string, extras [][2]string) error {
	for i, o := range outputs {
		for _, p := range inputs {
			if sameFile(o, p) {
				return errorf("output %s would overwrite an input file", o)
			}
		}
		for j := 0; j < i; j++ {
			if sameFile(o, outputs[j]) {
				return errorf("inputs %s and %s would both be written to %s; "+
					"rename one or sanitize them in separate runs", inputs[j], inputs[i], o)
			}
		}
	}
	var set [][2]string
	for _, e := range extras {
		if e[1] != "" {
			set = append(set, e)
		}
	}
	for k, e := range set {
		flag, path := e[0], e[1]
		for _, p := range inputs {
			if sameFile(path, p) {
				return errorf("%s %s is the same file as input %s", flag, path, p)
			}
		}
		for _, o := range outputs {
			if sameFile(path, o) {
				return errorf("%s %s is the same file as output %s", flag, path, o)
			}
		}
		for _, e2 := range set[:k] {
			if sameFile(path, e2[1]) {
				return errorf("%s %s and %s %s are the same file", e2[0], e2[1], flag, path)
			}
		}
	}
	return nil
}
