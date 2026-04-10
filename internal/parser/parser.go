// Package parser reads Vault client-export CSV files and returns raw records.
// It handles column name variations across Vault versions (e.g. "timestamp" vs
// "token_creation_time") and is tolerant of missing optional columns.
package parser

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

// RawRecord holds one row from a Vault activity-export CSV file.
// All values are kept as strings; normalization happens in the normalizer package.
type RawRecord struct {
	// Source tracks which file this record came from.
	Source string

	ClientID             string
	NamespaceID          string
	NamespacePath        string
	MountAccessor        string
	MountPath            string
	MountType            string
	AuthMethod           string
	ClientType           string
	TokenCreationTime    string // may be populated from legacy "timestamp" column
	ClientFirstUsageTime string
	EntityAliasName      string
}

// knownColumns maps all recognised (lowercased, trimmed) header variants to
// a canonical field name used by the column mapper below.
var knownColumns = map[string]string{
	"client_id":              "client_id",
	"namespace_id":           "namespace_id",
	"namespace_path":         "namespace_path",
	"mount_accessor":         "mount_accessor",
	"mount_path":             "mount_path",
	"mount_type":             "mount_type",
	"auth_method":            "auth_method",
	"client_type":            "client_type",
	"token_creation_time":    "token_creation_time",
	"client_first_usage_time": "client_first_usage_time",
	"entity_alias_name":      "entity_alias_name",
	// Legacy / alternative column names:
	"timestamp":              "token_creation_time", // Vault < 1.17
	"first_seen":             "client_first_usage_time",
	"namespace":              "namespace_path",
	"mount":                  "mount_path",
	"auth_backend":           "auth_method",
	"type":                   "client_type",
	"alias_name":             "entity_alias_name",
	"entity_alias":           "entity_alias_name",
}

// ParseFile opens path, detects the header layout, and returns one RawRecord
// per data row. Rows with a blank client_id are silently skipped (they are
// typically summary/total rows injected by some export tools).
func ParseFile(path string) ([]RawRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	return parseReader(f, path)
}

func parseReader(r io.Reader, source string) ([]RawRecord, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.LazyQuotes = true

	// Read header row.
	headers, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Build index: canonical field name → column index.
	colIndex := make(map[string]int, len(headers))
	for i, h := range headers {
		canonical, ok := knownColumns[strings.ToLower(strings.TrimSpace(h))]
		if ok {
			// First occurrence wins (handles duplicate column names gracefully).
			if _, exists := colIndex[canonical]; !exists {
				colIndex[canonical] = i
			}
		}
	}

	if _, ok := colIndex["client_id"]; !ok {
		return nil, fmt.Errorf("required column 'client_id' not found in %s", source)
	}

	get := func(row []string, field string) string {
		idx, ok := colIndex[field]
		if !ok || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}

	var records []RawRecord
	lineNum := 1 // 1 = header already consumed
	for {
		lineNum++
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Skip malformed rows but report them.
			fmt.Fprintf(os.Stderr, "warning: %s line %d: %v (skipped)\n", source, lineNum, err)
			continue
		}

		clientID := get(row, "client_id")
		if clientID == "" {
			continue // skip summary / blank rows
		}

		records = append(records, RawRecord{
			Source:               source,
			ClientID:             clientID,
			NamespaceID:          get(row, "namespace_id"),
			NamespacePath:        get(row, "namespace_path"),
			MountAccessor:        get(row, "mount_accessor"),
			MountPath:            get(row, "mount_path"),
			MountType:            get(row, "mount_type"),
			AuthMethod:           get(row, "auth_method"),
			ClientType:           get(row, "client_type"),
			TokenCreationTime:    get(row, "token_creation_time"),
			ClientFirstUsageTime: get(row, "client_first_usage_time"),
			EntityAliasName:      get(row, "entity_alias_name"),
		})
	}

	return records, nil
}
