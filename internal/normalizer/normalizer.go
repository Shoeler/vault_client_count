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

// BaseAlias returns the portion of an entity alias name before the first '@'
// character. If no '@' is present the full name is returned.
// Example: "alice@corp.com" → "alice", "sbishop@hashicorp.com" → "sbishop",
// "sbishop-t0" → "sbishop-t0".
func BaseAlias(name string) string {
	for i, ch := range name {
		if ch == '@' {
			return name[:i]
		}
	}
	return name
}

// StripTierSuffix removes a trailing "-t0", "-t1", or "-t2" suffix from name.
// Other suffixes are left unchanged.
// Example: "alice-t0" → "alice", "bob-t2" → "bob", "carol-t3" → "carol-t3".
func StripTierSuffix(name string) string {
	n := len(name)
	if n >= 3 && name[n-3] == '-' && name[n-2] == 't' && name[n-1] >= '0' && name[n-1] <= '2' {
		return name[:n-3]
	}
	return name
}

// aliasKey is the deduplication key for alias-based dedup: one record is
// allowed per (normalized alias, mount type) pair across all input files.
// Including the mount type prevents --dedup-alias from collapsing records
// across different auth methods (e.g. LDAP vs JWT); use --dedup-jwt for that.
type aliasKey struct {
	base      string
	mountType string
}

// dedupMountGroup maps mount types that represent the same identity provider
// to a single canonical value. OIDC and LDAP are treated as one group because
// the same person typically has the same username in both systems.
func dedupMountGroup(mt string) string {
	if mt == "oidc" {
		return "ldap"
	}
	return mt
}

// aliasKeyFor computes the dedup key for a record. It strips the domain suffix
// (at '@') and any trailing tier suffix ("-t0"/"-t1"/"-t2"), and scopes the
// key to the mount group so that only records of the same identity type
// collapse. OIDC and LDAP share a group; JWT remains separate (use
// --dedup-jwt for JWT vs LDAP/OIDC dedup).
func aliasKeyFor(r Record) aliasKey {
	mt := r.MountType
	if mt == "" {
		mt = r.AuthMethod
	}
	return aliasKey{
		base:      StripTierSuffix(BaseAlias(r.EntityAliasName)),
		mountType: dedupMountGroup(mt),
	}
}

// FindAliasDuplicates groups records by (BaseAlias, source file) and returns
// every group that contains more than one record. Records with a blank
// EntityAliasName or that are PKI clients are ignored. Groups are returned in
// the order the first member of each group appeared in records.
func FindAliasDuplicates(records []Record) [][]Record {
	type entry struct {
		key     aliasKey
		members []Record
	}
	index := make(map[aliasKey]int)
	var entries []entry

	for _, r := range records {
		if r.EntityAliasName == "" || IsPKIClient(r) {
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

// DeduplicateByAlias keeps at most one record per (BaseAlias, source file)
// combination. The same user authenticating via multiple mount accessors in
// the same file is collapsed to one record. Records with a blank
// EntityAliasName or that are PKI clients are always kept.
func DeduplicateByAlias(records []Record) []Record {
	seen := make(map[aliasKey]struct{}, len(records))
	out := make([]Record, 0, len(records))
	for _, r := range records {
		if r.EntityAliasName == "" || IsPKIClient(r) {
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

// isJWT reports whether r was authenticated via JWT.
func isJWT(r Record) bool {
	return r.MountType == "jwt" || r.AuthMethod == "jwt"
}

// DeduplicateJWT drops JWT records whose normalized alias (StripTierSuffix +
// BaseAlias) matches a non-JWT record's normalized alias in the same source
// file. This prevents the same person from being counted once for their LDAP
// or OIDC identity and again for their JWT identity. Records without an alias
// are always kept.
func DeduplicateJWT(records []Record) []Record {
	// Build global set of normalized aliases from all non-JWT records.
	nonJWTAliases := make(map[string]struct{})
	for _, r := range records {
		if isJWT(r) || r.EntityAliasName == "" {
			continue
		}
		norm := StripTierSuffix(BaseAlias(r.EntityAliasName))
		if norm != "" {
			nonJWTAliases[norm] = struct{}{}
		}
	}

	out := make([]Record, 0, len(records))
	for _, r := range records {
		if isJWT(r) && r.EntityAliasName != "" {
			norm := StripTierSuffix(BaseAlias(r.EntityAliasName))
			if _, match := nonJWTAliases[norm]; match {
				continue
			}
		}
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
