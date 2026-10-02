package provider

import (
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
