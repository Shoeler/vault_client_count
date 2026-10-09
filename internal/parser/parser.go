// Package parser reads Vault client-export CSV files and returns raw records.
// It handles column name variations across Vault versions (e.g. "timestamp" vs
// "token_creation_time") and is tolerant of missing optional columns.
package parser

import (
	"bufio"
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

	ClientID                    string
	EntityName                  string
	NamespaceID                 string
	NamespacePath               string
	MountAccessor               string
	MountPath                   string
	MountType                   string
	AuthMethod                  string
	ClientType                  string
	TokenCreationTime           string // may be populated from legacy "timestamp" column
	ClientFirstUsageTime        string
	EntityAliasName             string
	EntityAliasMetadataUsername string
}

// knownColumns maps all recognised (lowercased, trimmed) header variants to
// a canonical field name used by the column mapper below.
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
	// Legacy / alternative column names:
	"timestamp":              "token_creation_time", // Vault < 1.17
	"first_seen":             "client_first_usage_time",
	"client_first_used_time": "client_first_usage_time", // variant emitted by some Vault versions
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

// warnOut receives parser warnings. Tests may replace it.
var warnOut io.Writer = os.Stderr

// parseReader reads the CSV one physical line at a time and parses each line
// with its own csv.Reader. Vault export fields never contain newlines, so a
// record can never legitimately span lines. Parsing per line keeps LazyQuotes
// tolerance for stray quotes inside fields while preventing an unterminated
// opening quote from silently swallowing every following row into one field.
func parseReader(r io.Reader, source string) ([]RawRecord, error) {
	br := bufio.NewReader(r)
	lineNum := 0

	// nextRow returns the fields of the next non-blank line, or io.EOF.
	// malformed is true when the line contains an unterminated quoted field;
	// in that case the fields come from a plain comma split.
	nextRow := func() (row []string, malformed bool, err error) {
		for {
			line, readErr := br.ReadString('\n')
			if line == "" && readErr != nil {
				return nil, false, readErr
			}
			lineNum++
			if readErr != nil && readErr != io.EOF {
				return nil, false, readErr
			}
			row, malformed = parseLine(line)
			if row != nil {
				return row, malformed, nil
			}
			// Blank line: keep reading.
		}
	}

	// Read header row.
	headers, malformed, err := nextRow()
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if malformed {
		return nil, fmt.Errorf("read header: %s line %d: unterminated quoted field", source, lineNum)
	}

	// Strip a UTF-8 byte order mark so it does not corrupt the first header.
	if len(headers) > 0 {
		headers[0] = strings.TrimPrefix(headers[0], "\ufeff")
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
	for {
		row, malformed, err := nextRow()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", source, lineNum, err)
		}
		if malformed {
			fmt.Fprintf(warnOut, "warning: %s line %d: unterminated quoted field; "+
				"parsed by splitting on commas with quotes removed (check this row)\n", source, lineNum)
		}

		clientID := get(row, "client_id")
		if clientID == "" {
			continue // skip summary / blank rows
		}

		records = append(records, RawRecord{
			Source:                      source,
			ClientID:                    clientID,
			EntityName:                  get(row, "entity_name"),
			NamespaceID:                 get(row, "namespace_id"),
			NamespacePath:               get(row, "namespace_path"),
			MountAccessor:               get(row, "mount_accessor"),
			MountPath:                   get(row, "mount_path"),
			MountType:                   get(row, "mount_type"),
			AuthMethod:                  get(row, "auth_method"),
			ClientType:                  get(row, "client_type"),
			TokenCreationTime:           get(row, "token_creation_time"),
			ClientFirstUsageTime:        get(row, "client_first_usage_time"),
			EntityAliasName:             get(row, "entity_alias_name"),
			EntityAliasMetadataUsername: get(row, "entity_alias_metadata_username"),
		})
	}

	return records, nil
}

// parseLine parses one physical CSV line. It returns nil for a blank line.
//
// The line is parsed by a fresh csv.Reader with LazyQuotes, so a stray quote
// inside an unquoted field (a"b) is kept as a literal character. The reader
// cannot see past the end of the line, so an opening quote that is never
// closed shows up as a field containing the line's newline. Such a line is
// reported as malformed and re-split on commas with double quotes removed,
// so the row is still counted and its columns stay aligned as far as
// possible.
func parseLine(line string) (fields []string, malformed bool) {
	if !strings.HasSuffix(line, "\n") {
		line += "\n" // so an unterminated quote on the last line is detected too
	}
	cr := csv.NewReader(strings.NewReader(line))
	cr.TrimLeadingSpace = true
	cr.LazyQuotes = true
	// Rows may have fewer fields than the header (for example when trailing
	// empty columns were trimmed); get() treats missing fields as blank.
	cr.FieldsPerRecord = -1

	row, err := cr.Read()
	if err != nil {
		// io.EOF means a blank line. With LazyQuotes and FieldsPerRecord=-1
		// the reader reports no other errors for in-memory input.
		return nil, false
	}
	for _, f := range row {
		// csv.Reader folds "\r\n" into "\n", so checking for '\n' alone
		// catches runaway quotes for both line-ending styles.
		if strings.Contains(f, "\n") {
			raw := strings.TrimRight(line, "\r\n")
			parts := strings.Split(raw, ",")
			for i, p := range parts {
				parts[i] = strings.ReplaceAll(p, `"`, "")
			}
			return parts, true
		}
	}
	return row, false
}
