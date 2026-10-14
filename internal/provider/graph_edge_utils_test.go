package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

func TestParseGraphEdgeId(t *testing.T) {
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
			group, object, diags := parseGraphEdgeId(test.id, "object")
			if diags.HasError() != test.expectError {
				t.Fatalf("Unexpected diagnostics: %v", diags)
			}
			if !test.expectError && (group != test.expectedGroup || object != test.expectedObject) {
				t.Errorf("Expected %d/%s, got %d/%s.", test.expectedGroup, test.expectedObject, group, object)
			}
			// The ID made from the parsed group and object is the original ID.
			if !test.expectError && makeGraphEdgeId(group, object) != test.id {
				t.Errorf("Expected the ID %s to be made again, got %s.", test.id, makeGraphEdgeId(group, object))
			}
		})
	}
}

// Checks that the diagnostics contain a single error, with the given summary, on the given attribute.
func checkAttributeError(t *testing.T, diags diag.Diagnostics, attribute string, summary string) {
	t.Helper()

	if len(diags) != 1 || !diags.HasError() {
		t.Fatalf("Expected a single error, got: %v", diags)
	}

	d, ok := diags[0].(diag.DiagnosticWithPath)
	if !ok || !d.Path().Equal(path.Root(attribute)) || d.Summary() != summary {
		t.Errorf("Expected the error %q on %s, got: %v", summary, attribute, diags[0])
	}
}

func TestPermissionsGroupExists(t *testing.T) {
	fake, client := newFakeGraphServer(t)
	fake.missingGroups["4"] = true

	exists, diags := permissionsGroupExists(context.Background(), client, 3)
	if diags.HasError() || !exists {
		t.Errorf("Expected group 3 to exist, got %v (%v).", exists, diags)
	}
	if diags := checkPermissionsGroupExists(context.Background(), client, 3); len(diags) != 0 {
		t.Errorf("Expected no diagnostics for group 3, got: %v", diags)
	}

	exists, diags = permissionsGroupExists(context.Background(), client, 4)
	if diags.HasError() || exists {
		t.Errorf("Expected group 4 not to exist, got %v (%v).", exists, diags)
	}
	checkAttributeError(t, checkPermissionsGroupExists(context.Background(), client, 4), "group", "Group not found.")
}

func TestCollectionStatus(t *testing.T) {
	fake, client := newFakeGraphServer(t)
	fake.collections["5"] = `{"id": 5, "name": "Active", "archived": false, "is_personal": false}`
	fake.collections["6"] = `{"id": 6, "name": "Archived", "archived": true, "is_personal": false}`
	fake.collections["7"] = `{"id": 7, "name": "Personal", "personal_owner_id": 1, "is_personal": true}`
	fake.collections["8"] = `{"id": 8, "name": "Inside personal", "location": "/7/", "is_personal": true}`

	tests := map[string]struct {
		collection      string
		expectedStatus  collectionStatus
		expectedSummary string
	}{
		"root":            {collection: "root", expectedStatus: collectionStatusActive},
		"active":          {collection: "5", expectedStatus: collectionStatusActive},
		"archived":        {collection: "6", expectedStatus: collectionStatusMissing, expectedSummary: "Collection not found."},
		"missing":         {collection: "9", expectedStatus: collectionStatusMissing, expectedSummary: "Collection not found."},
		"personal":        {collection: "7", expectedStatus: collectionStatusPersonal, expectedSummary: "Personal collection."},
		"inside personal": {collection: "8", expectedStatus: collectionStatusPersonal, expectedSummary: "Personal collection."},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			status, diags := getCollectionStatus(context.Background(), client, test.collection)
			if diags.HasError() || status != test.expectedStatus {
				t.Errorf("Expected status %d, got %d (%v).", test.expectedStatus, status, diags)
			}

			diags = checkCollectionStatus(context.Background(), client, test.collection)
			if test.expectedSummary == "" {
				if len(diags) != 0 {
					t.Errorf("Expected no diagnostics, got: %v", diags)
				}
				return
			}
			checkAttributeError(t, diags, "collection", test.expectedSummary)
		})
	}
}
