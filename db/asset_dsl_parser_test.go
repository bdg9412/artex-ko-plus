package db

import (
	"reflect"
	"testing"
)

func TestParseDSLSQLStyleAssetQueries(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantSQL string
		wantArg []any
	}{
		{
			name:    "spaced fuzzy URL with single quotes",
			query:   "url = 'http://vuln-bank:5000'",
			wantSQL: "url ILIKE $1",
			wantArg: []any{"%http://vuln-bank:5000%"},
		},
		{
			name:    "spaced exact URL",
			query:   "url == 'http://vuln-bank:5000'",
			wantSQL: "url = $1",
			wantArg: []any{"http://vuln-bank:5000"},
		},
		{
			name:    "two spaced fields",
			query:   "service_type = 'http' AND service_name = 'vuln-bank'",
			wantSQL: "(service_type ILIKE $1) AND (service_name ILIKE $2)",
			wantArg: []any{"%http%", "%vuln-bank%"},
		},
		{
			name:    "SQL ILIKE maps to fuzzy",
			query:   "url ILIKE '%vuln-bank:5000%'",
			wantSQL: "url ILIKE $1",
			wantArg: []any{"%%vuln-bank:5000%%"},
		},
		{
			name:    "contains maps to fuzzy",
			query:   "url contains 'vuln-bank:5000'",
			wantSQL: "url ILIKE $1",
			wantArg: []any{"%vuln-bank:5000%"},
		},
		{
			name:    "single quote stays in bound argument",
			query:   "url = 'x'' OR 1=1 --'",
			wantSQL: "url ILIKE $1",
			wantArg: []any{"%x' OR 1=1 --%"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node, err := ParseDSL(tt.query)
			if err != nil {
				t.Fatalf("ParseDSL(%q): %v", tt.query, err)
			}
			gotSQL, gotArg, err := buildDSLWhere(node)
			if err != nil {
				t.Fatalf("buildDSLWhere(%q): %v", tt.query, err)
			}
			if gotSQL != tt.wantSQL || !reflect.DeepEqual(gotArg, tt.wantArg) {
				t.Fatalf("query=%q: SQL=%q args=%#v; want SQL=%q args=%#v", tt.query, gotSQL, gotArg, tt.wantSQL, tt.wantArg)
			}
		})
	}
}

func TestParseDSLRejectsUnsupportedSQLSyntax(t *testing.T) {
	for _, query := range []string{
		"unknown_field ILIKE '%vuln-bank%'",
		"port ILIKE '5000'",
		"SELECT * FROM assets",
	} {
		if _, err := ParseDSL(query); err == nil {
			t.Errorf("ParseDSL(%q) unexpectedly accepted unsupported syntax", query)
		}
	}
}
