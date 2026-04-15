// Package normalizer transforms raw Vault CSV records into a standardized form
// with consistent types, casing, and values.
package normalizer

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vault-csv-normalizer/internal/parser"
)

// Record is a fully normalized Vault client record.
type Record struct {
	Source               string
	ClientID             string
	NamespaceID          string
	NamespacePath        string
	MountAccessor        string
	MountPath            string
	MountType            string
	AuthMethod           string
	ClientType           string // normalized: entity | non-entity | acme | secret-sync | unknown
	TokenCreationTime    time.Time
	ClientFirstUsageTime time.Time
	EntityAliasName      string
}

// supportedSortKeys lists columns accepted by Sort.
var supportedSortKeys = map[string]bool{
	"namespace_path":         true,
	"client_type":            true,
	"token_creation_time":    true,
	"client_first_usage_time": true,
	"mount_accessor":         true,
	"mount_path":             true,
	"auth_method":            true,
	"source":                 true,
}

// Normalize converts a slice of raw records into normalized records.
func Normalize(raw []parser.RawRecord) []Record {
	out := make([]Record, 0, len(raw))
	for _, r := range raw {
		out = append(out, normalizeOne(r))
	}
	return out
}

func normalizeOne(r parser.RawRecord) Record {
	return Record{
		Source:               r.Source,
		ClientID:             r.ClientID,
		NamespaceID:          normalizeNamespaceID(r.NamespaceID),
		NamespacePath:        normalizeNamespacePath(r.NamespacePath),
		MountAccessor:        strings.TrimSpace(r.MountAccessor),
		MountPath:            normalizeMountPath(r.MountPath),
		MountType:            strings.ToLower(strings.TrimSpace(r.MountType)),
		AuthMethod:           strings.ToLower(strings.TrimSpace(r.AuthMethod)),
		ClientType:           normalizeClientType(r.ClientType),
		TokenCreationTime:    ParseTime(r.TokenCreationTime),
		ClientFirstUsageTime: ParseTime(r.ClientFirstUsageTime),
		EntityAliasName:      strings.TrimSpace(r.EntityAliasName),
	}
}

// normalizeNamespaceID returns "root" for blank / "root" IDs.
func normalizeNamespaceID(id string) string {
	id = strings.TrimSpace(id)
	if id == "" || strings.EqualFold(id, "root") {
		return "root"
	}
	return id
}

// normalizeNamespacePath ensures a trailing slash and maps empty → "[root]".
func normalizeNamespacePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "[root]" || strings.EqualFold(path, "root") {
		return "[root]"
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return path
}

// normalizeMountPath trims and ensures trailing slash.
func normalizeMountPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	return path
}

// clientTypeAliases maps various raw strings to a canonical client type.
var clientTypeAliases = map[string]string{
	"entity":                     "entity",
	"entity client":              "entity",
	"non-entity":                 "non-entity",
	"non_entity":                 "non-entity",
	"non-entity client":          "non-entity",
	"non_entity_client":          "non-entity",
	"nonentity":                  "non-entity",
	"acme":                       "acme",
	"acme client":                "acme",
	"secret-sync":                "secret-sync",
	"secret_sync":                "secret-sync",
	"secretsync":                 "secret-sync",
	"secrets sync":               "secret-sync",
	"secret sync":                "secret-sync",
}

func normalizeClientType(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	if canonical, ok := clientTypeAliases[key]; ok {
		return canonical
	}
	if key == "" {
		return "unknown"
	}
	return key
}

// timeFormats lists all timestamp formats Vault is known to emit.
var timeFormats = []string{
	time.RFC3339,
	time.RFC3339Nano,
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05 +0000 UTC",
	"2006-01-02 15:04:05Z",
	"2006-01-02",
	"01/02/2006",
}

// ParseTime parses a timestamp string using all Vault-known formats and returns
// a UTC time.Time. Returns the zero value for empty, "0", "N/A", or
// unrecognized input. Accepts the same formats as Vault activity exports.
func ParseTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" || raw == "N/A" {
		return time.Time{}
	}
	for _, layout := range timeFormats {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC()
		}
	}
	return time.Time{} // unparseable → zero value
}

// Deduplicate removes records with duplicate ClientIDs. When duplicates exist,
// the record with a non-empty MountPath is preferred over one with an empty
// MountPath; otherwise the first occurrence is kept.
func Deduplicate(records []Record) []Record {
	index := make(map[string]int, len(records)) // client_id → position in out
	out := make([]Record, 0, len(records))
	for _, r := range records {
		i, seen := index[r.ClientID]
		if !seen {
			index[r.ClientID] = len(out)
			out = append(out, r)
			continue
		}
		// Upgrade an empty-mount record if we now have a real mount path.
		if out[i].MountPath == "" && r.MountPath != "" {
			out[i] = r
		}
	}
	return out
}

// BaseAlias returns the portion of an entity alias name before the first '-'
// or '@' character. If neither is present the full name is returned.
// Example: "abc-123" → "abc", "alice@corp" → "alice", "plain" → "plain".
func BaseAlias(name string) string {
	for i, ch := range name {
		if ch == '-' || ch == '@' {
			return name[:i]
		}
	}
	return name
}

// aliasKey is the composite deduplication key for alias-based dedup:
// one record is allowed per base alias per auth method per source file.
type aliasKey struct {
	base       string
	authMethod string
	source     string
}

func aliasKeyFor(r Record) aliasKey {
	return aliasKey{
		base:       BaseAlias(r.EntityAliasName),
		authMethod: r.AuthMethod,
		source:     filepath.Base(r.Source),
	}
}

// FindAliasDuplicates groups records by (BaseAlias, AuthMethod, source file)
// and returns every group that contains more than one record. Records with a
// blank EntityAliasName are ignored. Groups are returned in the order the
// first member of each group appeared in records.
func FindAliasDuplicates(records []Record) [][]Record {
	type entry struct {
		key     aliasKey
		members []Record
	}
	index := make(map[aliasKey]int)
	var entries []entry

	for _, r := range records {
		if r.EntityAliasName == "" {
			continue
		}
		k := aliasKeyFor(r)
		if idx, ok := index[k]; ok {
			entries[idx].members = append(entries[idx].members, r)
		} else {
			index[k] = len(entries)
			entries = append(entries, entry{key: k, members: []Record{r}})
		}
	}

	var out [][]Record
	for _, e := range entries {
		if len(e.members) > 1 {
			out = append(out, e.members)
		}
	}
	return out
}

// DeduplicateByAlias keeps at most one record per (BaseAlias, AuthMethod,
// source file) combination. Records with a blank EntityAliasName are always
// kept.
func DeduplicateByAlias(records []Record) []Record {
	seen := make(map[aliasKey]struct{}, len(records))
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if r.EntityAliasName == "" {
			out = append(out, r)
			continue
		}
		k := aliasKeyFor(r)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

// IsPKIClient reports whether r is a PKI/cert client. It matches on either:
//   - client_type == "acme" (ACME protocol clients from the PKI secrets engine), or
//   - mount_accessor starting with "auth_cert" (cert auth method clients)
func IsPKIClient(r Record) bool {
	return r.ClientType == "acme" ||
		strings.HasPrefix(strings.ToLower(r.MountAccessor), "auth_cert")
}

// PartitionPKI splits records into two slices using the provided predicate.
// The original slice is not modified.
func PartitionPKI(records []Record, isPKI func(Record) bool) (pki, nonPKI []Record) {
	for _, r := range records {
		if isPKI(r) {
			pki = append(pki, r)
		} else {
			nonPKI = append(nonPKI, r)
		}
	}
	return
}

// FilterSince removes records whose TokenCreationTime is non-zero and strictly
// before since. Records with a zero TokenCreationTime (unknown/missing) are
// always kept.
func FilterSince(records []Record, since time.Time) []Record {
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if !r.TokenCreationTime.IsZero() && r.TokenCreationTime.Before(since) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// FilterSincePerSource applies per-file since filters to records. sinceBySource
// maps a key (matched against both the record's full Source path and its base
// name) to a cutoff time. Records whose Source matches a key and whose
// TokenCreationTime is non-zero and before the cutoff are excluded. Records
// whose Source does not match any key are always kept.
func FilterSincePerSource(records []Record, sinceBySource map[string]time.Time) []Record {
	if len(sinceBySource) == 0 {
		return records
	}
	out := make([]Record, 0, len(records))
	for _, r := range records {
		since, ok := sinceBySource[filepath.Base(r.Source)]
		if !ok {
			since, ok = sinceBySource[r.Source]
		}
		if ok && !r.TokenCreationTime.IsZero() && r.TokenCreationTime.Before(since) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// FilterByNamespace returns records whose NamespacePath contains substr.
func FilterByNamespace(records []Record, substr string) []Record {
	substr = strings.ToLower(substr)
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if strings.Contains(strings.ToLower(r.NamespacePath), substr) {
			out = append(out, r)
		}
	}
	return out
}

// FilterByClientType returns records whose ClientType matches (case-insensitive).
func FilterByClientType(records []Record, clientType string) []Record {
	want := normalizeClientType(clientType)
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if r.ClientType == want {
			out = append(out, r)
		}
	}
	return out
}

// Sort sorts records in-place by the given column key. Returns an error if
// the key is not recognized.
func Sort(records []Record, by string) error {
	by = strings.ToLower(strings.TrimSpace(by))
	if !supportedSortKeys[by] {
		return fmt.Errorf("unknown sort key %q; supported: namespace_path, client_type, token_creation_time, client_first_usage_time, mount_accessor, mount_path, auth_method, source", by)
	}

	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		switch by {
		case "namespace_path":
			return a.NamespacePath < b.NamespacePath
		case "client_type":
			return a.ClientType < b.ClientType
		case "token_creation_time":
			return a.TokenCreationTime.Before(b.TokenCreationTime)
		case "client_first_usage_time":
			return a.ClientFirstUsageTime.Before(b.ClientFirstUsageTime)
		case "mount_accessor":
			return a.MountAccessor < b.MountAccessor
		case "mount_path":
			return a.MountPath < b.MountPath
		case "auth_method":
			return a.AuthMethod < b.AuthMethod
		case "source":
			return a.Source < b.Source
		}
		return false
	})
	return nil
}
