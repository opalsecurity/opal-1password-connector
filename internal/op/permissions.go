package op

import (
	"maps"
	"slices"
)

// Vault permission names and dependencies follow 1Password's documented dependency table:
// https://www.1password.dev/cli/vault-permissions/

const businessAccountType = "BUSINESS"

var businessPermissions = []string{
	"view_items",
	"create_items",
	"edit_items",
	"archive_items",
	"delete_items",
	"view_and_copy_passwords",
	"view_item_history",
	"import_items",
	"export_items",
	"copy_and_share_items",
	"print_items",
	"manage_vault",
}

// Teams and Families accounts only have three coarse permissions.
var basicPermissions = []string{"allow_viewing", "allow_editing", "allow_managing"}

// permissionDependencies lists what each permission requires to be granted alongside it.
var permissionDependencies = map[string][]string{
	"create_items":            {"view_items"},
	"view_and_copy_passwords": {"view_items"},
	"edit_items":              {"view_and_copy_passwords", "view_items"},
	"archive_items":           {"edit_items", "view_and_copy_passwords", "view_items"},
	"delete_items":            {"edit_items", "view_and_copy_passwords", "view_items"},
	"view_item_history":       {"view_and_copy_passwords", "view_items"},
	"import_items":            {"create_items", "view_items"},
	"export_items":            {"view_item_history", "view_and_copy_passwords", "view_items"},
	"copy_and_share_items":    {"view_item_history", "view_and_copy_passwords", "view_items"},
	"print_items":             {"view_item_history", "view_and_copy_passwords", "view_items"},
	"allow_editing":           {"allow_viewing"},
}

var permissionDependents = invert(permissionDependencies)

// Permissions returns the vault permissions available for an `op account get` type.
func Permissions(accountType string) []string {
	if accountType == businessAccountType {
		return businessPermissions
	}
	return basicPermissions
}

// DefaultPermission is granted when Opal sends no access level.
func DefaultPermission(accountType string) string {
	return Permissions(accountType)[0]
}

// ExpandGrant returns permission plus everything it transitively depends on, sorted.
func ExpandGrant(permission string) []string {
	return closure(permission, permissionDependencies)
}

// ExpandRevoke returns permission plus everything that transitively depends on it, sorted.
func ExpandRevoke(permission string) []string {
	return closure(permission, permissionDependents)
}

// PrimaryPermission picks the single permission that best summarizes held: the one whose grant
// expansion is largest while staying within held. Opal stores one access level per group grant.
func PrimaryPermission(held []string) string {
	best, bestSize := "", 0
	for _, p := range held {
		expanded := ExpandGrant(p)
		if slices.ContainsFunc(expanded, func(e string) bool { return !slices.Contains(held, e) }) {
			continue
		}
		if len(expanded) > bestSize || (len(expanded) == bestSize && p < best) {
			best, bestSize = p, len(expanded)
		}
	}
	return best
}

// TopPermissions returns the held permissions that no other held permission's grant expansion
// covers, sorted. Each one is an access-level bundle: the permission plus everything it requires.
func TopPermissions(held []string) []string {
	var top []string
	for _, p := range held {
		covered := slices.ContainsFunc(held, func(q string) bool {
			return q != p && slices.Contains(ExpandGrant(q), p)
		})
		if !covered && !slices.Contains(top, p) {
			top = append(top, p)
		}
	}
	slices.Sort(top)
	return top
}

func closure(start string, edges map[string][]string) []string {
	seen := map[string]bool{}
	var visit func(string)
	visit = func(p string) {
		if seen[p] {
			return
		}
		seen[p] = true
		for _, next := range edges[p] {
			visit(next)
		}
	}
	visit(start)
	return slices.Sorted(maps.Keys(seen))
}

func invert(edges map[string][]string) map[string][]string {
	inverted := map[string][]string{}
	for from, tos := range edges {
		for _, to := range tos {
			inverted[to] = append(inverted[to], from)
		}
	}
	return inverted
}
