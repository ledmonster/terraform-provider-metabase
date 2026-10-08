package provider

import (
	"testing"
)

func TestParseGraphEdgeImportId(t *testing.T) {
	tests := map[string]struct {
		id             string
		expectedGroup  int64
		expectedObject string
		expectError    bool
	}{
		"database":          {id: "3/1", expectedGroup: 3, expectedObject: "1"},
		"root collection":   {id: "3/root", expectedGroup: 3, expectedObject: "root"},
		"missing object":    {id: "3/", expectError: true},
		"missing separator": {id: "3", expectError: true},
		"invalid group":     {id: "all/1", expectError: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			group, object, diags := parseGraphEdgeImportId(test.id, "object")
			if diags.HasError() != test.expectError {
				t.Fatalf("Unexpected diagnostics: %v", diags)
			}
			if !test.expectError && (group != test.expectedGroup || object != test.expectedObject) {
				t.Errorf("Expected %d/%s, got %d/%s.", test.expectedGroup, test.expectedObject, group, object)
			}
		})
	}
}
