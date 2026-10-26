package op

import (
	"slices"
	"testing"
)

func TestExpandGrant(t *testing.T) {
	got := ExpandGrant("export_items")
	want := []string{"export_items", "view_and_copy_passwords", "view_item_history", "view_items"}
	if !slices.Equal(got, want) {
		t.Fatalf("ExpandGrant(export_items) = %v, want %v", got, want)
	}
	if got := ExpandGrant("view_items"); !slices.Equal(got, []string{"view_items"}) {
		t.Fatalf("ExpandGrant(view_items) = %v", got)
	}
	if got := ExpandGrant("allow_editing"); !slices.Equal(got, []string{"allow_editing", "allow_viewing"}) {
		t.Fatalf("ExpandGrant(allow_editing) = %v", got)
	}
}

func TestExpandRevoke(t *testing.T) {
	got := ExpandRevoke("view_items")
	want := []string{
		"archive_items", "copy_and_share_items", "create_items", "delete_items", "edit_items", "export_items",
		"import_items", "print_items", "view_and_copy_passwords", "view_item_history", "view_items",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ExpandRevoke(view_items) = %v, want %v", got, want)
	}
	if got := ExpandRevoke("manage_vault"); !slices.Equal(got, []string{"manage_vault"}) {
		t.Fatalf("ExpandRevoke(manage_vault) = %v", got)
	}
}

func TestDependencyGraphIsAcyclicAndClosed(t *testing.T) {
	for permission, deps := range permissionDependencies {
		for _, dep := range deps {
			if slices.Contains(ExpandGrant(dep), permission) {
				t.Errorf("cycle: %s <-> %s", permission, dep)
			}
		}
	}
	cyclic := map[string][]string{"a": {"b"}, "b": {"a"}}
	if got := closure("a", cyclic); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("closure on a cycle = %v", got)
	}
}

func TestPermissionsByTier(t *testing.T) {
	if n := len(Permissions("BUSINESS")); n != 12 {
		t.Fatalf("BUSINESS has %d permissions, want 12", n)
	}
	for _, tier := range []string{"TEAM", "FAMILY", "INDIVIDUAL", ""} {
		if n := len(Permissions(tier)); n != 3 {
			t.Fatalf("%q has %d permissions, want 3", tier, n)
		}
	}
	if DefaultPermission("BUSINESS") != "view_items" || DefaultPermission("TEAM") != "allow_viewing" {
		t.Fatal("unexpected default permission")
	}
}

func TestTopPermissions(t *testing.T) {
	for _, tc := range []struct {
		held []string
		want []string
	}{
		{ExpandGrant("edit_items"), []string{"edit_items"}},
		{append(ExpandGrant("edit_items"), "manage_vault"), []string{"edit_items", "manage_vault"}},
		{append(ExpandGrant("export_items"), ExpandGrant("edit_items")...), []string{"edit_items", "export_items"}},
		{[]string{"view_items"}, []string{"view_items"}},
		{nil, nil},
	} {
		if got := TopPermissions(tc.held); !slices.Equal(got, tc.want) {
			t.Errorf("TopPermissions(%v) = %v, want %v", tc.held, got, tc.want)
		}
	}
}

func TestPrimaryPermission(t *testing.T) {
	for _, tc := range []struct {
		held []string
		want string
	}{
		{ExpandGrant("export_items"), "export_items"},
		{[]string{"view_items"}, "view_items"},
		{append(ExpandGrant("edit_items"), "manage_vault"), "edit_items"},
		{[]string{"edit_items"}, ""},
		{nil, ""},
	} {
		if got := PrimaryPermission(tc.held); got != tc.want {
			t.Errorf("PrimaryPermission(%v) = %q, want %q", tc.held, got, tc.want)
		}
	}
}
