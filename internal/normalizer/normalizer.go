// Package normalizer transforms raw Vault CSV records into a standardized form
// with consistent types, casing, and values.
package normalizer

import (
	"fmt"
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
		TokenCreationTime:    parseTime(r.TokenCreationTime),
		ClientFirstUsageTime: parseTime(r.ClientFirstUsageTime),
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
	"certificate":                "acme",
	"cert":                       "acme",
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

func parseTime(raw string) time.Time {
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

// IsPKIClient reports whether r is a PKI client, defined as any record whose
// mount_accessor starts with "auth_cert" (case-insensitive). The prefix check
// is done on the raw MountAccessor value since it is not lowercased during
// normalization.
func IsPKIClient(r Record) bool {
	return strings.HasPrefix(strings.ToLower(r.MountAccessor), "auth_cert")
}

// PartitionPKI splits records into two slices: PKI clients and non-PKI clients.
// The original slice is not modified.
func PartitionPKI(records []Record) (pki, nonPKI []Record) {
	for _, r := range records {
		if IsPKIClient(r) {
			pki = append(pki, r)
		} else {
			nonPKI = append(nonPKI, r)
		}
	}
	return
}

// FilterByNamespace returns records whose NamespacePath contains substr.
func FilterByNamespace(records []Record, substr string) []Record {
	substr = strings.ToLower(substr)
	out := records[:0]
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
	out := records[:0]
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
