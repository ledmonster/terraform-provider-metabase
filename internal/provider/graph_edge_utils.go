package provider

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/flovouin/terraform-provider-metabase/metabase"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
)

// Parses an import ID of the form `<group>/<object>`, where `<group>` is the ID of a permissions group.
func parseGraphEdgeImportId(id string, objectName string) (int64, string, diag.Diagnostics) {
	var diags diag.Diagnostics

	groupId, objectId, found := strings.Cut(id, "/")
	if !found || len(groupId) == 0 || len(objectId) == 0 {
		diags.AddError("Invalid import ID.", fmt.Sprintf("Expected an ID of the form <group>/<%s>, got: %s.", objectName, id))
		return 0, "", diags
	}

	groupIdInt, err := strconv.ParseInt(groupId, 10, 64)
	if err != nil {
		diags.AddError("Unable to convert the group ID to an integer.", groupId)
		return 0, "", diags
	}

	return groupIdInt, objectId, diags
}

// Returns an error if the given group is the Administrators group, for which Metabase does not allow changing
// permissions.
func checkGroupIsNotAdministrators(groupId int64) diag.Diagnostics {
	var diags diag.Diagnostics

	if groupId == metabase.AdministratorsPermissionsGroupId {
		diags.AddAttributeError(
			path.Root("group"),
			"Permissions for the Administrators group cannot be managed.",
			fmt.Sprintf("The Administrators group (ID %d) is always granted full access by Metabase, and its permissions cannot be changed.", metabase.AdministratorsPermissionsGroupId),
		)
	}

	return diags
}

// Returns whether the given permissions group exists.
func getPermissionsGroupExists(ctx context.Context, client *metabase.ClientWithResponses, groupId int64) (bool, diag.Diagnostics) {
	getResp, err := client.GetPermissionsGroupWithResponse(ctx, int(groupId))

	diags := checkMetabaseResponse(getResp, err, []int{200, 404}, "get permissions group")
	if diags.HasError() {
		return false, diags
	}

	return getResp.StatusCode() == 200, diags
}

// Returns an error if the given permissions group does not exist.
func checkPermissionsGroupExists(ctx context.Context, client *metabase.ClientWithResponses, groupId int64) diag.Diagnostics {
	exists, diags := getPermissionsGroupExists(ctx, client, groupId)
	if !diags.HasError() && !exists {
		diags.AddAttributeError(
			path.Root("group"),
			"Group not found.",
			fmt.Sprintf("The permissions group %d does not exist.", groupId),
		)
	}

	return diags
}

// The status of a collection, which defines whether its permissions are part of the collection graph.
type collectionStatus int

const (
	// The collection exists, and is neither archived nor personal. Its permissions are part of the collection graph, and
	// can be updated through it.
	collectionStatusActive collectionStatus = iota
	// The collection does not exist, or is archived. Its permissions are not part of the collection graph. Metabase
	// rejects updating the permissions of a collection which does not exist, but accepts updating those of an archived
	// collection.
	collectionStatusMissing
	// The collection is personal, or is inside a personal collection. Its permissions are fixed: they are not part of
	// the collection graph, and Metabase ignores them when updating it.
	collectionStatusPersonal
)

// Returns the status of the given collection. Metabase omits `none` from the collection graph, as well as the
// collections which are not active, so the graph alone cannot tell them apart.
func getCollectionStatus(ctx context.Context, client *metabase.ClientWithResponses, collectionId string) (collectionStatus, diag.Diagnostics) {
	var diags diag.Diagnostics

	// The root collection always exists, and is not personal.
	if collectionId == "root" {
		return collectionStatusActive, diags
	}

	getResp, err := client.GetCollectionWithResponse(ctx, collectionId)

	diags.Append(checkMetabaseResponse(getResp, err, []int{200, 404}, "get collection")...)
	if diags.HasError() {
		return collectionStatusMissing, diags
	}

	if getResp.StatusCode() == 404 || (getResp.JSON200.Archived != nil && *getResp.JSON200.Archived) {
		return collectionStatusMissing, diags
	}

	if getResp.JSON200.IsPersonal != nil && *getResp.JSON200.IsPersonal {
		return collectionStatusPersonal, diags
	}

	return collectionStatusActive, diags
}

// Returns an error if the permissions of the given collection cannot be updated through the collection graph (see
// `getCollectionStatus`).
func checkCollectionStatus(ctx context.Context, client *metabase.ClientWithResponses, collectionId string) diag.Diagnostics {
	status, diags := getCollectionStatus(ctx, client, collectionId)
	if diags.HasError() {
		return diags
	}

	switch status {
	case collectionStatusActive:
		// The permissions of the collection can be managed.
	case collectionStatusMissing:
		diags.AddAttributeError(
			path.Root("collection"),
			"Collection not found.",
			fmt.Sprintf("The collection %s does not exist, or is archived.", collectionId),
		)
	case collectionStatusPersonal:
		diags.AddAttributeError(
			path.Root("collection"),
			"Personal collection.",
			fmt.Sprintf("The collection %s is a personal collection, or is inside one. The permissions of personal collections are fixed, and cannot be changed.", collectionId),
		)
	}

	return diags
}
