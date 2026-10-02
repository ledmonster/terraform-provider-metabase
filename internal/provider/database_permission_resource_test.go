package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/flovouin/terraform-provider-metabase/internal/graphlock"
	"github.com/flovouin/terraform-provider-metabase/metabase"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Creates a permissions group directly using the Metabase API, to act as a group managed outside of Terraform.
// The group is deleted at the end of the test.
func testAccCreateBystanderGroup(t *testing.T, name string) int {
	t.Helper()

	response, err := testAccMetabaseClient.CreatePermissionsGroupWithResponse(context.Background(), metabase.CreatePermissionsGroupBody{
		Name: name,
	})
	if err != nil || response.StatusCode() != 200 {
		t.Fatalf("Failed to create permissions group: %v, %v", err, response)
	}

	groupId := response.JSON200.Id
	t.Cleanup(func() {
		_, _ = testAccMetabaseClient.DeletePermissionsGroupWithResponse(context.Background(), groupId)
	})

	return groupId
}

// Returns the raw permissions from the permissions graph for the given group and database, or an empty string if there
// are none.
func testAccGetDatabasePermissionsJson(groupId string, databaseId string) (string, error) {
	response, err := testAccMetabaseClient.GetPermissionsGraphWithResponse(context.Background())
	if err != nil {
		return "", err
	}
	if response.StatusCode() != 200 {
		return "", fmt.Errorf("Received unexpected response from the Metabase API when getting the permissions graph.")
	}

	permissions, ok := response.JSON200.Groups[groupId][databaseId]
	if !ok {
		return "", nil
	}

	b, err := json.Marshal(permissions)
	return string(b), err
}

// Returns the `create-queries` permission from the permissions graph for the given group and database.
func testAccGetCreateQueries(groupId string, databaseId string) (string, error) {
	raw, err := testAccGetDatabasePermissionsJson(groupId, databaseId)
	if err != nil || raw == "" {
		return "", err
	}

	var permissions map[string]any
	if err := json.Unmarshal([]byte(raw), &permissions); err != nil {
		return "", err
	}

	createQueries, ok := permissions["create-queries"]
	if !ok {
		// Metabase omits the permission when it is `no`.
		return string(metabase.PermissionsGraphDatabasePermissionsCreateQueries0No), nil
	}

	b, err := json.Marshal(createQueries)
	if err != nil {
		return "", err
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return string(b), nil
	}
	return s, nil
}

// Checks that the `create-queries` permission in Metabase matches the one from the resource in the state.
func testAccCheckDatabasePermissionExists(resourceName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Failed to find resource %s in state.", resourceName)
		}

		createQueries, err := testAccGetCreateQueries(rs.Primary.Attributes["group"], rs.Primary.Attributes["database"])
		if err != nil {
			return err
		}

		if createQueries != rs.Primary.Attributes["create_queries"] {
			return fmt.Errorf("Expected create-queries to be %q in Metabase, got %q.", rs.Primary.Attributes["create_queries"], createQueries)
		}

		return nil
	}
}

// Checks that the `create-queries` permission for the given group and database has the expected value in Metabase.
func testAccCheckCreateQueries(groupId func() string, databaseId string, expected string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		createQueries, err := testAccGetCreateQueries(groupId(), databaseId)
		if err != nil {
			return err
		}

		if createQueries != expected {
			return fmt.Errorf("Expected create-queries for group %s and database %s to be %q, got %q.", groupId(), databaseId, expected, createQueries)
		}

		return nil
	}
}

// Returns the value of an attribute of a resource in the state, to be used by checks in later steps.
func testAccStoreAttribute(resourceName string, attribute string, value *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("Failed to find resource %s in state.", resourceName)
		}

		*value = rs.Primary.Attributes[attribute]
		return nil
	}
}

func testAccDatabasePermissionResource(permissions string) string {
	return fmt.Sprintf(`
resource "metabase_permissions_group" "permission_a" {
  name = "🔑 Database permission A"
}

resource "metabase_permissions_group" "permission_b" {
  name = "🔑 Database permission B"
}

%s
`,
		permissions,
	)
}

func testAccDatabasePermission(name string, group string, createQueries string) string {
	return fmt.Sprintf(`
resource "metabase_database_permission" "%s" {
  group          = %s
  database       = 1
  view_data      = "unrestricted"
  create_queries = "%s"
}
`,
		name,
		group,
		createQueries,
	)
}

func TestAccDatabasePermissionResource(t *testing.T) {
	var bystanderGroupId string
	var groupB string
	bystanderGroup := func() string { return bystanderGroupId }
	getGroupB := func() string { return groupB }

	checkBystanderIsUntouched := testAccCheckCreateQueries(bystanderGroup, "1", string(metabase.PermissionsGraphDatabasePermissionsCreateQueries0QueryBuilder))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: resource.ComposeAggregateTestCheckFunc(
			testAccCheckDatabasePermissionDestroy,
			checkBystanderIsUntouched,
		),
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					// A group whose permissions are managed outside of Terraform, and should be left untouched.
					bystanderGroupId = strconv.Itoa(testAccCreateBystanderGroup(t, "🧍 Database permission bystander"))
					testAccSetDatabasePermissions(t, bystanderGroupId, "1", `{"view-data":"unrestricted","create-queries":"query-builder"}`)
				},
				Config: providerApiKeyConfig + testAccDatabasePermissionResource(
					testAccDatabasePermission("a", "metabase_permissions_group.permission_a.id", "query-builder")+
						testAccDatabasePermission("b", "metabase_permissions_group.permission_b.id", "query-builder-and-native"),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckDatabasePermissionExists("metabase_database_permission.a"),
					testAccCheckDatabasePermissionExists("metabase_database_permission.b"),
					resource.TestCheckResourceAttrPair("metabase_database_permission.a", "group", "metabase_permissions_group.permission_a", "id"),
					resource.TestCheckResourceAttr("metabase_database_permission.a", "database", "1"),
					resource.TestCheckResourceAttr("metabase_database_permission.a", "view_data", "unrestricted"),
					resource.TestCheckResourceAttr("metabase_database_permission.a", "create_queries", "query-builder"),
					resource.TestCheckResourceAttrSet("metabase_database_permission.a", "id"),
					testAccStoreAttribute("metabase_database_permission.b", "group", &groupB),
					checkBystanderIsUntouched,
				),
			},
			{
				ResourceName:      "metabase_database_permission.a",
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Removing a resource only resets its own edge. The other edges are left untouched.
				Config: providerApiKeyConfig + testAccDatabasePermissionResource(
					testAccDatabasePermission("a", "metabase_permissions_group.permission_a.id", "query-builder-and-native"),
				),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccCheckDatabasePermissionExists("metabase_database_permission.a"),
					resource.TestCheckResourceAttr("metabase_database_permission.a", "create_queries", "query-builder-and-native"),
					func(s *terraform.State) error {
						return testAccCheckRevokedDatabasePermissions(getGroupB(), func(*terraform.State) (string, error) { return "1", nil })(s)
					},
					checkBystanderIsUntouched,
				),
			},
		},
	})
}

// Sets the permissions for the given group and database directly using the Metabase API.
func testAccSetDatabasePermissions(t *testing.T, groupId string, databaseId string, permissions string) {
	t.Helper()

	var p metabase.PermissionsGraphDatabasePermissions
	if err := json.Unmarshal([]byte(permissions), &p); err != nil {
		t.Fatalf("Failed to parse permissions: %v", err)
	}

	diags := updateDatabasePermissions(context.Background(), testAccMetabaseClient, graphlock.NewPermissionsGraphTracker(), mustParseInt64(t, groupId), mustParseInt64(t, databaseId), func(*metabase.PermissionsGraphDatabasePermissions) (*metabase.PermissionsGraphDatabasePermissions, diag.Diagnostics) {
		return &p, nil
	})
	if diags.HasError() {
		t.Fatalf("Failed to set permissions: %v", diags)
	}
}

func mustParseInt64(t *testing.T, s string) int64 {
	t.Helper()

	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatalf("Failed to parse integer %q: %v", s, err)
	}

	return i
}

// Checks that the edges of destroyed resources no longer grant permissions to create queries.
func testAccCheckDatabasePermissionDestroy(s *terraform.State) error {
	for _, rs := range s.RootModule().Resources {
		if rs.Type != "metabase_database_permission" {
			continue
		}

		permissions, err := testAccGetDatabasePermissions(rs.Primary.Attributes["group"], rs.Primary.Attributes["database"])
		if err != nil {
			// The group may have been deleted along with its permissions.
			if strings.Contains(err.Error(), "contains no permissions") {
				continue
			}
			return err
		}

		if !isRevokedDatabasePermissions(*permissions, metabase.PermissionsGraphDatabasePermissionsViewData0Unrestricted) {
			b, _ := json.Marshal(permissions)
			return fmt.Errorf("Expected the permissions %s to be revoked, got: %s.", rs.Primary.ID, b)
		}
	}

	return nil
}

func TestAccDatabasePermissionResourceAdministrators(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      providerApiKeyConfig + testAccDatabasePermission("admin", "2", "query-builder"),
				ExpectError: regexp.MustCompile("Permissions for the Administrators group cannot be managed"),
			},
		},
	})
}

// Creates a collection directly using the Metabase API, and returns its ID. The collection is archived at the end of
// the test.
func testAccCreateCollection(t *testing.T, name string) string {
	t.Helper()

	response, err := testAccMetabaseClient.CreateCollectionWithResponse(context.Background(), metabase.CreateCollectionBody{
		Name: name,
	})
	if err != nil || response.StatusCode() != 200 {
		t.Fatalf("Failed to create collection: %v, %v", err, response)
	}

	id, err := response.JSON200.Id.MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to read the collection ID: %v", err)
	}
	collectionId := strings.Trim(string(id), `"`)

	t.Cleanup(func() {
		archived := true
		_, _ = testAccMetabaseClient.UpdateCollectionWithResponse(context.Background(), collectionId, metabase.UpdateCollectionBody{
			Archived: &archived,
		})
	})

	return collectionId
}

func testAccGraphEdgesParallel(collectionIds []string) string {
	config := ""
	for i, collectionId := range collectionIds {
		config += fmt.Sprintf(`
resource "metabase_permissions_group" "parallel_%[1]d" {
  name = "🏎️ Parallel %[1]d"
}

resource "metabase_database_permission" "parallel_%[1]d" {
  group          = metabase_permissions_group.parallel_%[1]d.id
  database       = 1
  view_data      = "unrestricted"
  create_queries = "query-builder"
}

resource "metabase_collection_permission" "parallel_%[1]d" {
  group      = metabase_permissions_group.parallel_%[1]d.id
  collection = "%[2]s"
  permission = "read"
}
`,
			i,
			collectionId,
		)
	}

	return config
}

// Creates many edges at once. Terraform applies them in parallel, which the provider should serialize.
func TestAccGraphEdgesParallel(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		t.Skipf("Acceptance tests skipped unless env '%s' set", resource.EnvTfAcc)
	}

	const count = 8

	// The collections are created one at a time beforehand, such that only the permissions are applied in parallel.
	collectionIds := make([]string, 0, count)
	for i := range count {
		collectionIds = append(collectionIds, testAccCreateCollection(t, fmt.Sprintf("🏎️ Parallel %d", i)))
	}

	checks := []resource.TestCheckFunc{}
	for i := range count {
		checks = append(checks,
			testAccCheckDatabasePermissionExists(fmt.Sprintf("metabase_database_permission.parallel_%d", i)),
			testAccCheckCollectionPermissionExists(fmt.Sprintf("metabase_collection_permission.parallel_%d", i)),
		)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: resource.ComposeAggregateTestCheckFunc(
			testAccCheckDatabasePermissionDestroy,
			testAccCheckCollectionPermissionDestroy,
		),
		Steps: []resource.TestStep{
			{
				Config: providerApiKeyConfig + testAccGraphEdgesParallel(collectionIds),
				Check:  resource.ComposeAggregateTestCheckFunc(checks...),
			},
		},
	})
}

func testAccDatabasePermissionDrift() string {
	return fmt.Sprintf(`
resource "metabase_permissions_group" "drift" {
  name = "🌊 Database permission drift"
}

resource "metabase_database_permission" "drift" {
  group          = metabase_permissions_group.drift.id
  database       = 1
  view_data      = "unrestricted"
  create_queries = %s
}
`,
		// Metabase prunes the table set to "no" from its response, which should not be reported as a change.
		perTableCreateQueries(6),
	)
}

func TestAccDatabasePermissionResourceDrift(t *testing.T) {
	var groupId string
	getGroup := func() string { return groupId }

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatabasePermissionDestroy,
		Steps: []resource.TestStep{
			{
				// The framework fails the step if the plan after the apply is not empty, i.e. if the reshaped response
				// is reported as a change.
				Config: providerApiKeyConfig + testAccDatabasePermissionDrift(),
				Check: resource.ComposeAggregateTestCheckFunc(
					testAccStoreAttribute("metabase_database_permission.drift", "group", &groupId),
				),
			},
			{
				// A change made outside of Terraform (e.g. in the Metabase interface) is reported.
				PreConfig: func() {
					testAccSetDatabasePermissions(t, groupId, "1", `{"view-data":"unrestricted","create-queries":"query-builder-and-native"}`)
				},
				Config:             providerApiKeyConfig + testAccDatabasePermissionDrift(),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Applying the configuration reverts the change.
				Config: providerApiKeyConfig + testAccDatabasePermissionDrift(),
				Check: resource.ComposeAggregateTestCheckFunc(
					func(s *terraform.State) error {
						createQueries, err := testAccGetCreateQueries(getGroup(), "1")
						if err != nil {
							return err
						}
						if createQueries == string(metabase.PermissionsGraphDatabasePermissionsCreateQueries0QueryBuilderAndNative) {
							return fmt.Errorf("Expected the change made outside of Terraform to be reverted.")
						}
						return nil
					},
				),
			},
		},
	})
}

// A fake Metabase API serving the permissions and collection graphs. Like Metabase, it rejects updates made from an
// outdated revision with a 409 status, and only updates the edges present in the request.
type fakeGraphServer struct {
	mutex sync.Mutex
	// The graphs, by API path.
	graphs map[string]*fakeGraph
	// The number of updates rejected because of a conflict, whether forced or not.
	conflicts int
	// The bodies of the updates that were accepted.
	acceptedUpdates []map[string]map[string]json.RawMessage
}

type fakeGraph struct {
	revision int
	groups   map[string]map[string]json.RawMessage
}

func newFakeGraphServer(t *testing.T) (*fakeGraphServer, *metabase.ClientWithResponses) {
	t.Helper()

	f := &fakeGraphServer{
		graphs: map[string]*fakeGraph{
			"/permissions/graph": {groups: map[string]map[string]json.RawMessage{}},
			"/collection/graph":  {groups: map[string]map[string]json.RawMessage{}},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(server.Close)

	client, err := metabase.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatalf("Failed to create the client: %v", err)
	}

	return f, client
}

func (f *fakeGraphServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	graph, ok := f.graphs[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		f.writeGraph(w, graph.revision, graph.groups)
	case http.MethodPut:
		var body struct {
			Revision int                                   `json:"revision"`
			Groups   map[string]map[string]json.RawMessage `json:"groups"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if body.Revision != graph.revision {
			f.conflicts++
			http.Error(w, "Looks like someone else edited the permissions and your data is out of date.", http.StatusConflict)
			return
		}

		for groupId, edges := range body.Groups {
			if graph.groups[groupId] == nil {
				graph.groups[groupId] = map[string]json.RawMessage{}
			}
			for objectId, permissions := range edges {
				graph.groups[groupId][objectId] = permissions
			}
		}
		graph.revision++
		f.acceptedUpdates = append(f.acceptedUpdates, body.Groups)

		// Like Metabase, only the edges that were sent are returned.
		f.writeGraph(w, graph.revision, body.Groups)
	default:
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}
}

func (f *fakeGraphServer) writeGraph(w http.ResponseWriter, revision int, groups map[string]map[string]json.RawMessage) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"revision": revision,
		"groups":   groups,
	})
}

func TestWriteDatabasePermissionsOnlySendsConfiguredOptionalPermissions(t *testing.T) {
	fake, client := newFakeGraphServer(t)
	r := &DatabasePermissionResource{MetabaseBaseResource{metabaseResourceData: metabaseResourceData{
		client:           client,
		permissionsGraph: graphlock.NewPermissionsGraphTracker(),
	}}}

	previousDownload := types.ObjectValueMust(accessPermissionsObjectType.AttrTypes, map[string]attr.Value{
		"schemas": types.StringValue("full"),
	})
	plan := DatabasePermissionResourceModel{
		Group:         types.Int64Value(3),
		Database:      types.Int64Value(1),
		ViewData:      types.StringValue("unrestricted"),
		CreateQueries: types.StringValue("query-builder"),
		// A value from the previous state, which should not be sent back as it is not in the configuration.
		Download:  previousDownload,
		DataModel: types.ObjectUnknown(accessPermissionsObjectType.AttrTypes),
		Details:   types.StringUnknown(),
	}
	config := plan
	config.Download = types.ObjectNull(accessPermissionsObjectType.AttrTypes)
	config.DataModel = types.ObjectNull(accessPermissionsObjectType.AttrTypes)
	config.Details = types.StringNull()

	_, diags := r.writeDatabasePermissions(context.Background(), &plan, config)
	if diags.HasError() {
		t.Fatalf("Unexpected error: %v", diags)
	}

	if len(fake.acceptedUpdates) != 1 {
		t.Fatalf("Expected a single update, got %d.", len(fake.acceptedUpdates))
	}
	var sent map[string]any
	if err := json.Unmarshal(fake.acceptedUpdates[0]["3"]["1"], &sent); err != nil {
		t.Fatalf("Failed to parse the sent permissions: %v", err)
	}
	for _, key := range []string{"download", "data-model", "details"} {
		if _, ok := sent[key]; ok {
			t.Errorf("Expected %s not to be sent, got: %v", key, sent)
		}
	}
}

func TestMakeComparableDatabasePermissions(t *testing.T) {
	parse := func(s string) metabase.PermissionsGraphDatabasePermissions {
		var p metabase.PermissionsGraphDatabasePermissions
		if err := json.Unmarshal([]byte(s), &p); err != nil {
			t.Fatalf("Failed to parse permissions: %v", err)
		}
		return p
	}

	a, errA := makeComparableDatabasePermissions(parse(`{"view-data":"unrestricted","create-queries":{"PUBLIC":{"1":"query-builder","2":"no"}},"download":{"schemas":"full"}}`))
	b, errB := makeComparableDatabasePermissions(parse(`{"create-queries":{"PUBLIC":{"2":"no","1":"query-builder"}},"view-data":"unrestricted"}`))
	if errA != nil || errB != nil {
		t.Fatalf("Unexpected errors: %v, %v", errA, errB)
	}
	if string(a) != string(b) {
		t.Errorf("Expected the key order and other permissions to be ignored, got %s and %s.", a, b)
	}
}

// Declares an edge with the lowest permissions, i.e. the same permissions as a revoked edge. Unlike the
// `metabase_permissions_graph` resource, this resource does not consider such an edge absent, as it is its own edge.
func TestAccDatabasePermissionResourceLowestPermissions(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCheckDatabasePermissionDestroy,
		Steps: []resource.TestStep{
			{
				Config: providerApiKeyConfig + `
resource "metabase_permissions_group" "lowest" {
  name = "🔒 Lowest permissions"
}

resource "metabase_database_permission" "lowest" {
  group          = metabase_permissions_group.lowest.id
  database       = 1
  view_data      = "unrestricted"
  create_queries = "no"
  download = {
    schemas = "none"
  }
}
`,
				Check: func(s *terraform.State) error {
					group, err := testAccResourceAttribute(s, "metabase_database_permission.lowest", "group")
					if err != nil {
						return err
					}
					return testAccCheckRevokedDatabasePermissions(group, func(*terraform.State) (string, error) { return "1", nil })(s)
				},
			},
			{
				ResourceName:      "metabase_database_permission.lowest",
				ImportState:       true,
				ImportStateVerify: true,
				// Metabase omits revoked permissions, so an imported `download` permission set to `none` is read as null.
				ImportStateVerifyIgnore: []string{"download"},
			},
		},
	})
}

func TestAccDatabasePermissionResourceInvalidDefaultViewData(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerApiKeyConfig + `
resource "metabase_database_permission" "invalid" {
  group             = 1
  database          = 1
  view_data         = "unrestricted"
  create_queries    = "no"
  default_view_data = "sandboxed"
}
`,
				ExpectError: regexp.MustCompile("Invalid default view data permission"),
			},
		},
	})
}

// Returns the value of an attribute of a resource in the state.
func testAccResourceAttribute(s *terraform.State, resourceName string, attribute string) (string, error) {
	rs, ok := s.RootModule().Resources[resourceName]
	if !ok {
		return "", fmt.Errorf("Failed to find resource %s in state.", resourceName)
	}

	return rs.Primary.Attributes[attribute], nil
}
