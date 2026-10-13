// Package sanitizer pseudonymizes Vault client-activity export CSVs so they
// can be shared. It is a Go port of scripts/sanitize_csv.py and produces
// byte-identical output for the same salt; see scripts/README.md for the
// behaviour specification.
//
// Every value vault-csv-normalizer compares (client IDs, alias names, mount
// paths, accessors, namespaces) is replaced with a keyed HMAC-SHA256 pseudonym
// that preserves equality, blankness and the structure the tool's logic relies
// on (alias '@' domain split, -t0/-t1/-t2 tier suffixes, the auth_cert
// accessor prefix, root namespace forms, trailing slashes). Vault vocabulary
// and timestamps pass through unchanged. Unrecognized columns are dropped.
package sanitizer

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Column recognition (mirrors knownColumns in internal/parser/parser.go)
// ---------------------------------------------------------------------------

var knownColumns = map[string]string{
	"client_id":                      "client_id",
	"entity_name":                    "entity_name",
	"namespace_id":                   "namespace_id",
	"namespace_path":                 "namespace_path",
	"mount_accessor":                 "mount_accessor",
	"mount_path":                     "mount_path",
	"mount_type":                     "mount_type",
	"auth_method":                    "auth_method",
	"client_type":                    "client_type",
	"token_creation_time":            "token_creation_time",
	"client_first_usage_time":        "client_first_usage_time",
	"entity_alias_name":              "entity_alias_name",
	"entity_alias_metadata.username": "entity_alias_metadata_username",
	// Legacy / alternative column names.
	"timestamp":    "token_creation_time",
	"first_seen":   "client_first_usage_time",
	"namespace":    "namespace_path",
	"mount":        "mount_path",
	"auth_backend": "auth_method",
	"type":         "client_type",
	"alias_name":   "entity_alias_name",
	"entity_alias": "entity_alias_name",
}

// extraSafeColumns are Vault export columns the normalizer does not read but
// that carry no customer identifiers. Values are still validated.
var extraSafeColumns = map[string]string{
	"client_first_used_time": "extra_timestamp",
	"local_entity_alias":     "extra_boolean",
}

// Policy names.
const (
	polClientID    = "client_id"
	polEntityName  = "entity_name"
	polNamespaceID = "namespace_id"
	polNamespace   = "namespace_path"
	polAccessor    = "mount_accessor"
	polMountPath   = "mount_path"
	polPassthrough = "passthrough"
	polTimestamp   = "timestamp"
	polAlias       = "alias"
	polBoolean     = "boolean"
	polKept        = "kept"
)

// policyFor maps a canonical column name to its policy.
var policyFor = map[string]string{
	"client_id":                      polClientID,
	"entity_name":                    polEntityName,
	"namespace_id":                   polNamespaceID,
	"namespace_path":                 polNamespace,
	"mount_accessor":                 polAccessor,
	"mount_path":                     polMountPath,
	"mount_type":                     polPassthrough,
	"auth_method":                    polPassthrough,
	"client_type":                    polPassthrough,
	"token_creation_time":            polTimestamp,
	"client_first_usage_time":        polTimestamp,
	"entity_alias_name":              polAlias,
	"entity_alias_metadata_username": polAlias,
	"extra_timestamp":                polTimestamp,
	"extra_boolean":                  polBoolean,
}

// Well-known Vault auth method and secrets engine type names. Mount path and
// accessor segments that exactly match one (case-insensitive) are preserved.
var wellKnownMountWords = setOf(strings.Fields(`
auth secret secrets sys identity cubbyhole token
ldap oidc jwt approle kubernetes k8s aws gcp azure cert userpass github okta
radius saml kerberos oci cf alicloud spiffe scep
pki acme kv transit database ssh totp consul nomad rabbitmq terraform ad
openldap kmip transform keymgmt gcpkms mongodbatlas
`))

// formatWords may appear in output cells because the sanitizer emits them
// itself; they are excluded from the leak check.
var formatWords = setOf([]string{"root", "entity", "domain", "example", "nsid", "mnt", "acc", "redacted"})

var booleanValues = setOf([]string{"", "true", "false", "0", "1", "t", "f", "yes", "no"})

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\n?$`)
	// tierRe is case-sensitive, like StripTierSuffix. The optional newline
	// mirrors Python's '$', which also matches before a final newline.
	tierRe = regexp.MustCompile(`-t[0-2]\n?$`)
)

const (
	leakMinLen   = 4
	hexLenLong   = 16
	hexLenShort  = 12
	maxLeakCells = 1000
)

// SanitizeError is returned for bad input or a failed safety check.
type SanitizeError struct{ Msg string }

func (e *SanitizeError) Error() string { return e.Msg }

func errorf(format string, a ...interface{}) error {
	return &SanitizeError{Msg: fmt.Sprintf(format, a...)}
}

func setOf(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, s := range items {
		m[s] = struct{}{}
	}
	return m
}

func has(m map[string]struct{}, k string) bool {
	_, ok := m[k]
	return ok
}

// pyIsSpace reports whether r is whitespace per Python's str.isspace.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// pyStrip mirrors Python's str.strip().
func pyStrip(s string) string { return strings.TrimFunc(s, pyIsSpace) }

func canonicalColumn(header string) (string, bool) {
	key := strings.ToLower(pyStrip(header))
	if c, ok := knownColumns[key]; ok {
		return c, true
	}
	c, ok := extraSafeColumns[key]
	return c, ok
}

// tokens returns the lowercased alphanumeric tokens (length >= 4) of an
// already-lowercased value, used by the leak check.
func tokens(low string) []string {
	var out []string
	start := -1
	for i := 0; i <= len(low); i++ {
		isTok := i < len(low) && (low[i] >= '0' && low[i] <= '9' || low[i] >= 'a' && low[i] <= 'z')
		if isTok {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 && i-start >= leakMinLen {
			out = append(out, low[start:i])
		}
		start = -1
	}
	return out
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// Timestamp rounding (only formats vault-csv-normalizer's ParseTime accepts)
// ---------------------------------------------------------------------------

var (
	tsRe     = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})([T ])([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]+)?(.*)$`)
	offsetRe = regexp.MustCompile(`^([+-])([0-9]{2}):([0-9]{2})$`)
)

func daysIn(year, month int) int {
	switch month {
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	}
	return 31
}

// RoundTimestampToDay truncates a parseable timestamp to midnight UTC, keeping
// its layout. Values the normalizer cannot parse (and date-only values) are
// returned unchanged. Timestamps with a numeric offset are converted to UTC
// first and emitted with a 'Z' suffix.
func RoundTimestampToDay(value string) string {
	raw := pyStrip(value)
	m := tsRe.FindStringSubmatch(raw)
	if m == nil {
		return value
	}
	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	year, month, day := atoi(m[1]), atoi(m[2]), atoi(m[3])
	sep := m[4]
	hh, mi, ss := atoi(m[5]), atoi(m[6]), atoi(m[7])
	tail := m[9]
	if year < 1 || month < 1 || month > 12 || day < 1 || day > daysIn(year, month) ||
		hh > 23 || mi > 59 || ss > 59 {
		return value
	}
	dt := time.Date(year, time.Month(month), day, hh, mi, ss, 0, time.UTC)
	var newTail string
	if sep == "T" {
		switch tail {
		case "Z":
			newTail = "Z"
		case "":
			newTail = ""
		default:
			om := offsetRe.FindStringSubmatch(tail)
			if om == nil {
				return value
			}
			oh, omin := atoi(om[2]), atoi(om[3])
			if oh > 23 || omin > 59 {
				return value
			}
			offset := time.Duration(oh)*time.Hour + time.Duration(omin)*time.Minute
			if om[1] == "+" {
				dt = dt.Add(-offset)
			} else {
				dt = dt.Add(offset)
			}
			newTail = "Z"
		}
	} else {
		if tail != "Z" && tail != " +0000 UTC" {
			return value
		}
		newTail = tail
	}
	return fmt.Sprintf("%04d-%02d-%02d%s00:00:00%s", dt.Year(), int(dt.Month()), dt.Day(), sep, newTail)
}

// ---------------------------------------------------------------------------
// Pseudonymization
// ---------------------------------------------------------------------------

type cacheKey struct{ category, value string }

// Sanitizer is a keyed, consistent pseudonymizer shared across all files in a
// run.
type Sanitizer struct {
	salt            []byte
	roundTimestamps bool
	cache           map[cacheKey]string // (category, original) -> pseudonym
	reverse         map[cacheKey]string // (category, pseudonym) -> original
	filenames       map[string]string   // input file stem -> output file stem

	// Leak-check state (all lowercased).
	originalWholes map[string]struct{}
	originalTokens map[string]struct{}
	generated      map[string]struct{} // generated pseudonyms and their tokens
	allowed        map[string]struct{}
}

// New returns a Sanitizer keyed by salt, which must be at least 16 bytes.
func New(salt []byte, roundTimestamps bool) (*Sanitizer, error) {
	if len(salt) < 16 {
		return nil, errorf("salt must be at least 16 bytes")
	}
	s := &Sanitizer{
		salt:            salt,
		roundTimestamps: roundTimestamps,
		cache:           map[cacheKey]string{},
		reverse:         map[cacheKey]string{},
		filenames:       map[string]string{},
		originalWholes:  map[string]struct{}{},
		originalTokens:  map[string]struct{}{},
		generated:       map[string]struct{}{},
		allowed:         map[string]struct{}{},
	}
	for w := range wellKnownMountWords {
		s.allowed[w] = struct{}{}
	}
	for w := range formatWords {
		s.allowed[w] = struct{}{}
	}
	s.allowed["[root]"] = struct{}{}
	return s, nil
}

func (s *Sanitizer) digest(category, value string) string {
	mac := hmac.New(sha256.New, s.salt)
	mac.Write([]byte(category + "\x00" + value))
	return hex.EncodeToString(mac.Sum(nil))
}

// FilenameCategory is the HMAC domain (and mapping category) for output file
// name pseudonyms.
const FilenameCategory = "filename"

// Filename returns the pseudonymous output stem for an input file stem (the
// input's base name without its .csv extension): "export-" followed by the
// first 12 hex characters of HMAC-SHA256(salt, "filename\x00" + stem). It is
// case-sensitive. File names are kept out of the leak-check state, so they
// never change the sanitized content.
func (s *Sanitizer) Filename(stem string) string {
	if hit, ok := s.filenames[stem]; ok {
		return hit
	}
	p := "export-" + s.digest(FilenameCategory, stem)[:hexLenShort]
	s.filenames[stem] = p
	return p
}

func (s *Sanitizer) record(category, original, pseudonym string) error {
	if prev, ok := s.reverse[cacheKey{category, pseudonym}]; ok && prev != original {
		return errorf("pseudonym collision in category '%s'; rerun with a different salt", category)
	}
	s.reverse[cacheKey{category, pseudonym}] = original
	s.cache[cacheKey{category, original}] = pseudonym
	low := strings.ToLower(original)
	s.originalWholes[low] = struct{}{}
	for _, t := range tokens(low) {
		s.originalTokens[t] = struct{}{}
	}
	plow := strings.ToLower(pseudonym)
	s.generated[plow] = struct{}{}
	for _, t := range tokens(plow) {
		s.generated[t] = struct{}{}
	}
	return nil
}

func (s *Sanitizer) hashed(category, value string, builder func(h string) string) (string, error) {
	if hit, ok := s.cache[cacheKey{category, value}]; ok {
		return hit, nil
	}
	pseudonym := builder(s.digest(category, value))
	if err := s.record(category, value, pseudonym); err != nil {
		return "", err
	}
	return pseudonym, nil
}

// uuidFromHex builds a UUID-shaped string with version 4 and RFC 4122 variant
// bits set.
func uuidFromHex(h string) string {
	n, _ := strconv.ParseInt(h[16:17], 16, 32)
	variant := "89ab"[n&3]
	return h[0:8] + "-" + h[8:12] + "-4" + h[13:16] + "-" + string(variant) + h[17:20] + "-" + h[20:32]
}

// preserveWord keeps a Vault vocabulary word as-is and marks it as allowed.
func (s *Sanitizer) preserveWord(word string) string {
	s.allowed[strings.ToLower(word)] = struct{}{}
	return word
}

// -- column policies --------------------------------------------------------

func (s *Sanitizer) clientID(v string) (string, error) {
	if uuidRe.MatchString(v) {
		return s.hashed("client_id", v, uuidFromHex)
	}
	n := minInt(maxInt(runeLen(v), hexLenLong), 64)
	return s.hashed("client_id", v, func(h string) string { return h[:n] })
}

func (s *Sanitizer) entityName(v string) (string, error) {
	return s.hashed("entity_name", v, func(h string) string { return "entity-" + h[:hexLenLong] })
}

func (s *Sanitizer) namespaceID(v string) (string, error) {
	if strings.ToLower(v) == "root" {
		return v, nil
	}
	return s.hashed("namespace_id", v, func(h string) string { return "nsid-" + h[:hexLenShort] })
}

func (s *Sanitizer) namespacePath(v string) (string, error) {
	if v == "[root]" || strings.ToLower(v) == "root" {
		return v, nil
	}
	if hit, ok := s.cache[cacheKey{"namespace_path", v}]; ok {
		return hit, nil
	}
	segs := strings.Split(v, "/")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		p, err := s.hashed("ns_segment", seg, func(h string) string { return "ns-" + h[:hexLenShort] })
		if err != nil {
			return "", err
		}
		segs[i] = p
	}
	result := strings.Join(segs, "/")
	if err := s.record("namespace_path", v, result); err != nil {
		return "", err
	}
	return result, nil
}

func (s *Sanitizer) mountPath(v string) (string, error) {
	if hit, ok := s.cache[cacheKey{"mount_path", v}]; ok {
		return hit, nil
	}
	segs := strings.Split(v, "/")
	for i, seg := range segs {
		switch {
		case seg == "":
		case has(wellKnownMountWords, strings.ToLower(seg)):
			segs[i] = s.preserveWord(seg)
		default:
			p, err := s.hashed("mount_segment", seg, func(h string) string { return "mnt-" + h[:hexLenShort] })
			if err != nil {
				return "", err
			}
			segs[i] = p
		}
	}
	result := strings.Join(segs, "/")
	if err := s.record("mount_path", v, result); err != nil {
		return "", err
	}
	return result, nil
}

func (s *Sanitizer) mountAccessor(v string) (string, error) {
	if hit, ok := s.cache[cacheKey{"mount_accessor", v}]; ok {
		return hit, nil
	}
	h := s.digest("mount_accessor", v)
	parts := strings.Split(v, "_")
	var result string
	if len(parts) >= 2 {
		prefix := make([]string, 0, len(parts))
		for _, part := range parts[:len(parts)-1] {
			switch {
			case has(wellKnownMountWords, strings.ToLower(part)):
				prefix = append(prefix, s.preserveWord(part))
			case part == "":
				prefix = append(prefix, part)
			default:
				p, err := s.hashed("accessor_part", part, func(d string) string { return "x" + d[:8] })
				if err != nil {
					return "", err
				}
				prefix = append(prefix, p)
			}
		}
		n := minInt(maxInt(runeLen(parts[len(parts)-1]), hexLenShort), 64)
		result = strings.Join(append(prefix, h[:n]), "_")
	} else {
		result = "acc_" + h[:hexLenShort]
	}
	// PKI detection (prefix "auth_cert", case-insensitive) must not change.
	origPKI := strings.HasPrefix(strings.ToLower(v), "auth_cert")
	if origPKI != strings.HasPrefix(strings.ToLower(result), "auth_cert") {
		if origPKI {
			result = s.preserveWord(v[:4]) + "_" + v[5:9] + "_" + h[:hexLenShort]
			s.allowed[strings.ToLower(v[5:9])] = struct{}{}
		} else {
			result = "acc_" + h[:hexLenShort]
		}
	}
	if err := s.record("mount_accessor", v, result); err != nil {
		return "", err
	}
	return result, nil
}

func (s *Sanitizer) aliasCore(core string) (string, error) {
	if core == "" {
		return core, nil
	}
	if uuidRe.MatchString(core) {
		return s.hashed("alias", core, uuidFromHex)
	}
	return s.hashed("alias", core, func(h string) string { return "u" + h[:hexLenLong] })
}

// alias pseudonymizes an alias while preserving BaseAlias/StripTierSuffix.
//
// alias = base ['@' domain]; base = core [tier]. The core is mapped with a
// keyed, case-sensitive hash shared by entity_alias_name and
// entity_alias_metadata.username, the tier suffix is kept literally, and the
// domain becomes a separate consistent token.
func (s *Sanitizer) alias(v string) (string, error) {
	if hit, ok := s.cache[cacheKey{"alias_full", v}]; ok {
		return hit, nil
	}
	base, domain := v, ""
	at := false
	if i := strings.Index(v, "@"); i >= 0 {
		base, domain, at = v[:i], v[i+1:], true
	}
	tier := ""
	if tierRe.MatchString(base) {
		base, tier = base[:len(base)-3], base[len(base)-3:]
	}
	core, err := s.aliasCore(base)
	if err != nil {
		return "", err
	}
	result := core + tier
	if at {
		if domain != "" {
			d, err := s.hashed("domain", domain, func(h string) string {
				return "domain-" + h[:hexLenShort] + ".example"
			})
			if err != nil {
				return "", err
			}
			result += "@" + d
		} else {
			result += "@"
		}
	}
	if err := s.record("alias_full", v, result); err != nil {
		return "", err
	}
	return result, nil
}

func (s *Sanitizer) allow(low string) {
	s.allowed[low] = struct{}{}
	for _, t := range tokens(low) {
		s.allowed[t] = struct{}{}
	}
}

// SanitizeCell applies a column policy to one cell value.
func (s *Sanitizer) SanitizeCell(policy, value string) (string, error) {
	v := pyStrip(value)
	switch policy {
	case polPassthrough:
		s.allow(strings.ToLower(v))
		return v, nil
	case polTimestamp:
		s.allow(strings.ToLower(v))
		if s.roundTimestamps {
			return RoundTimestampToDay(v), nil
		}
		return v, nil
	case polBoolean:
		if has(booleanValues, strings.ToLower(v)) {
			return v, nil
		}
		return "redacted", nil
	}
	if v == "" {
		return v, nil
	}
	switch policy {
	case polClientID:
		return s.clientID(v)
	case polEntityName:
		return s.entityName(v)
	case polNamespaceID:
		return s.namespaceID(v)
	case polNamespace:
		return s.namespacePath(v)
	case polMountPath:
		return s.mountPath(v)
	case polAccessor:
		return s.mountAccessor(v)
	case polAlias:
		return s.alias(v)
	}
	return "", errorf("unknown policy %q", policy)
}

// MappingRow is one original-to-pseudonym entry.
type MappingRow struct{ Category, Original, Pseudonym string }

// MappingRows returns every mapping, sorted by (category, original).
func (s *Sanitizer) MappingRows() []MappingRow {
	rows := make([]MappingRow, 0, len(s.cache)+len(s.filenames))
	for k, p := range s.cache {
		rows = append(rows, MappingRow{k.category, k.value, p})
	}
	for stem, p := range s.filenames {
		rows = append(rows, MappingRow{FilenameCategory, stem, p})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Category != rows[j].Category {
			return rows[i].Category < rows[j].Category
		}
		return rows[i].Original < rows[j].Original
	})
	return rows
}

// ---------------------------------------------------------------------------
// CSV reading and writing with Python csv-module semantics
// ---------------------------------------------------------------------------

// lineReader splits input into lines with universal-newline recognition
// ("\n", "\r" and "\r\n") but without translating the terminators, like a
// Python text file opened with newline="".
type lineReader struct {
	br      *bufio.Reader
	pending []string
}

func newLineReader(r io.Reader) *lineReader {
	return &lineReader{br: bufio.NewReaderSize(r, 1<<20)}
}

func (l *lineReader) unread(line string) { l.pending = append(l.pending, line) }

func (l *lineReader) readLine() (string, error) {
	if n := len(l.pending); n > 0 {
		line := l.pending[n-1]
		l.pending = l.pending[:n-1]
		return line, nil
	}
	var buf []byte
	for {
		b, err := l.br.ReadByte()
		if err != nil {
			if len(buf) > 0 {
				return string(buf), nil
			}
			return "", err
		}
		buf = append(buf, b)
		if b == '\n' {
			return string(buf), nil
		}
		if b == '\r' {
			if nb, err := l.br.Peek(1); err == nil && nb[0] == '\n' {
				l.br.ReadByte()
				buf = append(buf, '\n')
			}
			return string(buf), nil
		}
	}
}

// csvReader mimics Python's csv.reader with the default (excel) dialect plus
// skipinitialspace=True and strict=False.
type csvReader struct{ lr *lineReader }

const (
	stStartRecord = iota
	stStartField
	stInField
	stInQuoted
	stQuoteInQuoted
	stEatCRNL
)

const eol = -1

// bom is the UTF-8 byte order mark.
const bom = "\xef\xbb\xbf"

// read returns the next record, which may be empty for a blank line, or
// io.EOF when the input is exhausted.
func (r *csvReader) read() ([]string, error) {
	state := stStartRecord
	fields := []string{}
	var field []byte
	save := func() {
		fields = append(fields, string(field))
		field = field[:0]
	}
	process := func(c int) {
		switch state {
		case stStartRecord:
			if c == eol {
				return
			}
			if c == '\n' || c == '\r' {
				state = stEatCRNL
				return
			}
			state = stStartField
			fallthrough
		case stStartField:
			switch {
			case c == '\n' || c == '\r' || c == eol:
				save()
				if c == eol {
					state = stStartRecord
				} else {
					state = stEatCRNL
				}
			case c == '"':
				state = stInQuoted
			case c == ' ':
				// skipinitialspace
			case c == ',':
				save()
			default:
				field = append(field, byte(c))
				state = stInField
			}
		case stInField:
			switch {
			case c == '\n' || c == '\r' || c == eol:
				save()
				if c == eol {
					state = stStartRecord
				} else {
					state = stEatCRNL
				}
			case c == ',':
				save()
				state = stStartField
			default:
				field = append(field, byte(c))
			}
		case stInQuoted:
			switch {
			case c == eol:
			case c == '"':
				state = stQuoteInQuoted
			default:
				field = append(field, byte(c))
			}
		case stQuoteInQuoted:
			switch {
			case c == '"':
				field = append(field, '"')
				state = stInQuoted
			case c == ',':
				save()
				state = stStartField
			case c == '\n' || c == '\r' || c == eol:
				save()
				if c == eol {
					state = stStartRecord
				} else {
					state = stEatCRNL
				}
			default:
				field = append(field, byte(c))
				state = stInField
			}
		case stEatCRNL:
			if c == eol {
				state = stStartRecord
			}
		}
	}
	for {
		line, err := r.lr.readLine()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			if len(field) != 0 || state == stInQuoted {
				save()
				return fields, nil
			}
			return nil, io.EOF
		}
		for i := 0; i < len(line); i++ {
			process(int(line[i]))
		}
		process(eol)
		if state == stStartRecord {
			return fields, nil
		}
	}
}

// writeRow mimics Python's csv.writer (QUOTE_MINIMAL) for one row.
func writeRow(w *bufio.Writer, fields []string, term string) {
	if len(fields) == 1 && fields[0] == "" {
		w.WriteString(`""`)
		w.WriteString(term)
		return
	}
	for i, f := range fields {
		if i > 0 {
			w.WriteByte(',')
		}
		if strings.ContainsAny(f, ",\"\r\n") {
			w.WriteByte('"')
			w.WriteString(strings.ReplaceAll(f, `"`, `""`))
			w.WriteByte('"')
		} else {
			w.WriteString(f)
		}
	}
	w.WriteString(term)
}

// pyRepr approximates Python's repr() for a str, used in error messages.
func pyRepr(s string) string {
	quote := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\udc%02x`, s[i])
		case byte(r) == quote && r < 0x80:
			b.WriteByte('\\')
			b.WriteByte(quote)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case !unicode.IsPrint(r) && r != ' ':
			switch {
			case r < 0x100:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r < 0x10000:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
		i += size
	}
	b.WriteByte(quote)
	return b.String()
}

// ---------------------------------------------------------------------------
// File processing
// ---------------------------------------------------------------------------

// planColumns returns the kept column indices, their policies, and the names
// of dropped columns.
func planColumns(headers []string, keepExtra map[string]bool) (kept []int, policies []string, dropped []string) {
	for i, h := range headers {
		if canonical, ok := canonicalColumn(h); ok {
			kept = append(kept, i)
			policies = append(policies, policyFor[canonical])
		} else if keepExtra[strings.ToLower(pyStrip(h))] {
			kept = append(kept, i)
			policies = append(policies, polKept)
		} else {
			dropped = append(dropped, h)
		}
	}
	return
}

// SanitizeFile sanitizes one CSV, verifies it, and atomically moves it into
// place. keepExtra holds lowercased names of unrecognized columns to pass
// through. It returns the number of data rows. On any failure the temporary
// output is removed and outPath is left untouched.
func SanitizeFile(s *Sanitizer, inPath, outPath string, keepExtra map[string]bool, log io.Writer) (int, error) {
	if log == nil {
		log = os.Stderr
	}
	started := time.Now()
	f, err := os.Open(inPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	lr := newLineReader(f)

	first, err := lr.readLine()
	if err != nil && err != io.EOF {
		return 0, err
	}
	if pyStrip(first) == "" {
		return 0, errorf("%s: file is empty or has no header row", inPath)
	}
	hasBOM := strings.HasPrefix(first, bom)
	if hasBOM {
		first = first[len(bom):]
	}
	terminator := "\n"
	if strings.HasSuffix(first, "\r\n") {
		terminator = "\r\n"
	}
	lr.unread(first)
	reader := &csvReader{lr: lr}
	headers, err := reader.read()
	if err != nil {
		return 0, errorf("%s: cannot parse header: %v", inPath, err)
	}
	foundID := false
	for _, h := range headers {
		if c, ok := canonicalColumn(h); ok && c == "client_id" {
			foundID = true
		}
	}
	if !foundID {
		return 0, errorf("%s: required column 'client_id' not found; is this a Vault client export?", inPath)
	}
	kept, policies, dropped := planColumns(headers, keepExtra)
	if len(dropped) > 0 {
		names := make([]string, len(dropped))
		for i, h := range dropped {
			names[i] = pyStrip(h)
		}
		fmt.Fprintf(log, "%s: dropping %d unrecognized column(s) (may contain customer data): %s\n",
			inPath, len(dropped), strings.Join(names, ", "))
		fmt.Fprintf(log, "%s: dropped columns are also removed from the header; use "+
			"--keep-columns to pass specific columns through unchanged\n", inPath)
	}

	outDir := filepath.Dir(absPath(outPath))
	tmp, err := os.CreateTemp(outDir, ".sanitize-*.csv")
	if err != nil {
		return 0, err
	}
	tmpPath := tmp.Name()
	done := false
	defer func() {
		if !done {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	outHeaders := make([]string, len(kept))
	for j, i := range kept {
		outHeaders[j] = headers[i]
	}
	bw := bufio.NewWriterSize(tmp, 1<<20)
	if hasBOM {
		bw.WriteString(bom)
	}
	writeRow(bw, outHeaders, terminator)
	rowsIn, extraFieldsRows := 0, 0
	nHeader := len(headers)
	for {
		row, err := reader.read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		if len(row) == 0 {
			continue // blank line; the Go csv reader skips these too
		}
		rowsIn++
		if len(row) > nHeader {
			extraFieldsRows++
		}
		outRow := make([]string, 0, len(kept))
		for j, i := range kept {
			if i >= len(row) {
				break // short row: keep it short
			}
			if policies[j] == polKept {
				outRow = append(outRow, row[i])
				continue
			}
			cell, err := s.SanitizeCell(policies[j], row[i])
			if err != nil {
				return 0, err
			}
			outRow = append(outRow, cell)
		}
		writeRow(bw, outRow, terminator)
	}
	if err := bw.Flush(); err != nil {
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if extraFieldsRows > 0 {
		fmt.Fprintf(log, "%s: %d row(s) had more fields than the header; extra fields "+
			"were dropped\n", inPath, extraFieldsRows)
	}
	rowsOut, err := verifyOutput(s, tmpPath, outHeaders)
	if err != nil {
		return 0, err
	}
	if rowsOut != rowsIn {
		return 0, errorf("%s: row count mismatch (input %d, output %d)", inPath, rowsIn, rowsOut)
	}
	// CreateTemp makes the file 0600; give the shareable output normal permissions.
	umask := syscall.Umask(0)
	syscall.Umask(umask)
	if err := os.Chmod(tmpPath, os.FileMode(0o666&^umask)); err != nil {
		return 0, err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		return 0, err
	}
	done = true

	elapsed := time.Since(started).Seconds()
	size := int64(0)
	if st, err := os.Stat(inPath); err == nil {
		size = st.Size()
	}
	rate := 0.0
	if elapsed > 0 {
		rate = float64(size) / 1e6 / elapsed
	}
	fmt.Fprintf(log, "%s -> %s: %d data rows, %d columns kept, %d dropped, %.2fs (%.1f MB/s)\n",
		inPath, outPath, rowsIn, len(kept), len(dropped), elapsed, rate)
	return rowsIn, nil
}

func absPath(p string) string {
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

// verifyOutput re-scans a sanitized file for original values and returns its
// data row count.
//
// Each output cell is checked as a whole and as alphanumeric tokens against
// the set of original values seen in pseudonymized columns. Vault vocabulary,
// passthrough column values and tokens the sanitizer generated itself are
// exempt. Offending values are never printed, only their location.
func verifyOutput(s *Sanitizer, path string, outHeaders []string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	reader := &csvReader{lr: newLineReader(f)}
	type leak struct{ row, col int }
	var leaks []leak
	rows := 0
	if _, err := reader.read(); err != nil && err != io.EOF { // header
		return 0, err
	}
	for {
		row, err := reader.read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
		if len(row) == 0 {
			continue
		}
		rows++
		for col, cell := range row {
			low := strings.ToLower(pyStrip(cell))
			if low == "" {
				continue
			}
			if has(s.originalWholes, low) && runeLen(low) >= leakMinLen &&
				!has(s.allowed, low) && !has(s.generated, low) {
				leaks = append(leaks, leak{rows, col})
				continue
			}
			for _, tok := range tokens(low) {
				if has(s.originalTokens, tok) && !has(s.allowed, tok) && !has(s.generated, tok) {
					leaks = append(leaks, leak{rows, col})
					break
				}
			}
		}
		if len(leaks) > maxLeakCells {
			break
		}
	}
	if len(leaks) > 0 {
		shown := leaks
		if len(shown) > 10 {
			shown = shown[:10]
		}
		where := make([]string, len(shown))
		for i, l := range shown {
			col := strconv.Itoa(l.col)
			if l.col < len(outHeaders) {
				col = pyRepr(outHeaders[l.col])
			}
			where[i] = fmt.Sprintf("row %d column %s", l.row, col)
		}
		more := ""
		if len(leaks) > 10 {
			more = ", ..."
		}
		return 0, errorf("leak check FAILED: %d cell(s) still contain an original value (%s%s). "+
			"The output file was deleted. If a --keep-columns column is listed, it "+
			"shares values with pseudonymized columns; drop it.",
			len(leaks), strings.Join(where, ", "), more)
	}
	return rows, nil
}
