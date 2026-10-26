package op

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
)

// FakeAccount is an in-memory 1Password account that answers `op` argv like the real CLI. It backs
// the tests and OP_FAKE=1 local mode.
type FakeAccount struct {
	mu sync.Mutex

	Type string
	// SelfID is the user `op whoami` reports, i.e. the connector's own identity.
	SelfID       string
	Users        []User
	Groups       []Group
	Vaults       []Vault
	GroupMembers map[string][]string
	VaultUsers   map[string]map[string][]string
	VaultGroups  map[string]map[string][]string

	// Calls records every argv received, for assertions.
	Calls [][]string
	// Fail, if set, is consulted before each command; a non-nil error is returned instead.
	Fail func(args []string) error
}

// NewDemoAccount returns a Business account seeded with sample users.
func NewDemoAccount() *FakeAccount {
	return &FakeAccount{
		Type:   businessAccountType,
		SelfID: "UCONNECTOR",
		Users: []User{
			{ID: "UCONNECTOR", Name: "Opal Connector", Email: "admin@example.com", State: "ACTIVE"},
			{ID: "UALICE", Name: "Alice", Email: "alice@example.com", State: "ACTIVE"},
			{ID: "UBOB", Name: "Bob", Email: "bob@example.com", State: "ACTIVE"},
			{ID: "UCAROL", Name: "Carol", Email: "carol@example.com", State: "ACTIVE"},
			{ID: "UDAVE", Name: "Dave", Email: "dave@example.com", State: "SUSPENDED"},
			{ID: "UBADEMAIL", Name: "Shared Login", Email: "shared-login", State: "ACTIVE"},
		},
		Groups: []Group{
			{ID: "GADMINS", Name: "Administrators", Description: "Administrators of this account", State: "ACTIVE"},
			{ID: "GENG", Name: "Engineering", Description: "All engineers", State: "ACTIVE"},
			{
				ID:          "GONCALL",
				Name:        "On-call",
				Description: "Current on-call rotation",
				State:       "ACTIVE",
			},
		},
		Vaults: []Vault{
			{ID: "VCLOUDFLARE", Name: "Cloudflare Break-glass", Description: "Shared Cloudflare admin login"},
			{ID: "VPRODDB", Name: "Production Database"},
			{ID: "VMARKETING", Name: "Shared Marketing"},
			{ID: "VPERSONAL", Name: "Employee", Type: "PERSONAL"},
		},
		GroupMembers: map[string][]string{
			"GADMINS": {"UCONNECTOR"},
			"GENG":    {"UALICE", "UBOB"},
			"GONCALL": {"UBOB"},
		},
		VaultUsers: map[string]map[string][]string{
			"VPRODDB":    {"UALICE": ExpandGrant("export_items")},
			"VMARKETING": {"UCAROL": {"view_items"}},
			"VPERSONAL":  {"UCONNECTOR": {"view_items"}},
		},
		// Like a real Business account, Administrators hold only manage_vault on shared vaults.
		VaultGroups: map[string]map[string][]string{
			"VCLOUDFLARE": {"GONCALL": ExpandGrant("view_and_copy_passwords"), "GADMINS": {"manage_vault"}},
			"VPRODDB":     {"GADMINS": {"manage_vault"}},
			"VMARKETING":  {"GADMINS": {"manage_vault"}},
		},
	}
}

func (f *FakeAccount) Exec() Exec {
	return func(_ context.Context, args, _ []string, _ string) ([]byte, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.Calls = append(f.Calls, slices.Clone(args))
		if f.Fail != nil {
			if err := f.Fail(args); err != nil {
				return nil, err
			}
		}
		parsed := parseArgs(args)
		if parsed.command == "signin" {
			return []byte("fake-session-token\n"), nil
		}
		out, err := f.handle(parsed)
		if err != nil {
			return nil, Classify("[ERROR] " + err.Error())
		}
		return json.Marshal(out)
	}
}

type fakeArgs struct {
	command    string
	positional string
	flags      map[string]string
}

func parseArgs(args []string) fakeArgs {
	parsed := fakeArgs{flags: map[string]string{}}
	var words []string
	for i := 0; i < len(args); i++ {
		if name, ok := strings.CutPrefix(args[i], "--"); ok {
			if name, value, ok := strings.Cut(name, "="); ok {
				parsed.flags[name] = value
			} else if name == "raw" || name == "no-input" {
				parsed.flags[name] = ""
			} else if i+1 < len(args) {
				parsed.flags[name] = args[i+1]
				i++
			}
			continue
		}
		words = append(words, args[i])
	}
	for n := len(words); n > 0; n-- {
		if _, ok := fakeCommands[strings.Join(words[:n], " ")]; ok {
			parsed.command = strings.Join(words[:n], " ")
			parsed.positional = strings.Join(words[n:], " ")
			break
		}
	}
	return parsed
}

var fakeCommands = map[string]bool{
	"signin": true, "whoami": true, "account list": true, "account add": true, "account get": true,
	"user list": true, "group list": true, "group get": true, "group user list": true,
	"group user grant": true, "group user revoke": true, "vault list": true, "vault get": true,
	"vault user list": true, "vault group list": true, "vault user grant": true,
	"vault user revoke": true, "vault group grant": true, "vault group revoke": true,
}

func (f *FakeAccount) handle(a fakeArgs) (any, error) {
	switch a.command {
	case "account list":
		return []map[string]string{
			{
				"url":          "fake.1password.com",
				"email":        "admin@example.com",
				"account_uuid": "FAKEACCOUNT",
			},
		}, nil
	case "account add":
		return nil, nil
	case "whoami":
		return map[string]string{"user_uuid": f.SelfID}, nil
	case "account get":
		return map[string]string{"type": f.Type}, nil
	case "user list":
		return f.Users, nil
	case "group list":
		return f.Groups, nil
	case "group get":
		return f.group(a.positional)
	case "group user list":
		if _, err := f.group(a.positional); err != nil {
			return nil, err
		}
		return f.usersByID(f.GroupMembers[a.positional]), nil
	case "group user grant", "group user revoke":
		return nil, f.groupWrite(a)
	case "vault list":
		// Like the real CLI, the list omits descriptions and types; only `vault get` has them. Without
		// --user it lists only vaults the caller can view items in, omitting manage-only ones.
		userID, forUser := a.flags["user"]
		if !forUser {
			userID = f.SelfID
		}
		vaults := []Vault{}
		for _, v := range f.Vaults {
			held := f.heldPermissions(v.ID, userID)
			if len(held) > 0 && (forUser || slices.Contains(held, "view_items")) {
				vaults = append(vaults, Vault{ID: v.ID, Name: v.Name})
			}
		}
		return vaults, nil
	case "vault get":
		return f.vault(a.positional)
	case "vault user list":
		if _, err := f.vault(a.positional); err != nil {
			return nil, err
		}
		users := []User{}
		for _, u := range f.usersByID(slices.Sorted(maps.Keys(f.VaultUsers[a.positional]))) {
			u.Permissions = f.VaultUsers[a.positional][u.ID]
			users = append(users, u)
		}
		return users, nil
	case "vault group list":
		if _, err := f.vault(a.positional); err != nil {
			return nil, err
		}
		groups := []Group{}
		for _, id := range slices.Sorted(maps.Keys(f.VaultGroups[a.positional])) {
			g, _ := f.group(id)
			g.Permissions = f.VaultGroups[a.positional][id]
			groups = append(groups, g)
		}
		return groups, nil
	case "vault user grant", "vault user revoke":
		return nil, f.vaultWrite(a, "user", &f.VaultUsers)
	case "vault group grant", "vault group revoke":
		return nil, f.vaultWrite(a, "group", &f.VaultGroups)
	}
	return nil, fmt.Errorf("unknown command")
}

func (f *FakeAccount) groupWrite(a fakeArgs) error {
	groupID, userID := a.flags["group"], a.flags["user"]
	if _, err := f.group(groupID); err != nil {
		return err
	}
	if _, err := f.user(userID); err != nil {
		return err
	}
	members := f.GroupMembers[groupID]
	isMember := slices.Contains(members, userID)
	if strings.HasSuffix(a.command, "grant") {
		if isMember {
			return fmt.Errorf("the user is already a member of the group")
		}
		f.GroupMembers[groupID] = append(members, userID)
		return nil
	}
	if !isMember {
		return fmt.Errorf("the user isn't a member of the group")
	}
	f.GroupMembers[groupID] = slices.DeleteFunc(
		members,
		func(id string) bool { return id == userID },
	)
	return nil
}

func (f *FakeAccount) vaultWrite(
	a fakeArgs,
	principal string,
	grants *map[string]map[string][]string,
) error {
	vaultID, principalID := a.flags["vault"], a.flags[principal]
	if _, err := f.vault(vaultID); err != nil {
		return err
	}
	var err error
	if principal == "user" {
		_, err = f.user(principalID)
	} else {
		_, err = f.group(principalID)
	}
	if err != nil {
		return err
	}
	if *grants == nil {
		*grants = map[string]map[string][]string{}
	}
	if (*grants)[vaultID] == nil {
		(*grants)[vaultID] = map[string][]string{}
	}
	held := (*grants)[vaultID][principalID]
	requested := strings.Split(a.flags["permissions"], ",")
	if strings.HasSuffix(a.command, "grant") {
		for _, p := range requested {
			if !slices.Contains(held, p) {
				held = append(held, p)
			}
		}
		slices.Sort(held)
		(*grants)[vaultID][principalID] = held
		return nil
	}
	if len(held) == 0 {
		return fmt.Errorf("the accessor doesn't have any permissions in the vault")
	}
	held = slices.DeleteFunc(
		slices.Clone(held),
		func(p string) bool { return slices.Contains(requested, p) },
	)
	if len(held) == 0 {
		delete((*grants)[vaultID], principalID)
	} else {
		(*grants)[vaultID][principalID] = held
	}
	return nil
}

func (f *FakeAccount) user(id string) (User, error) {
	for _, u := range f.Users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, fmt.Errorf("%q isn't a user in this account", id)
}

func (f *FakeAccount) group(id string) (Group, error) {
	for _, g := range f.Groups {
		if g.ID == id {
			return g, nil
		}
	}
	return Group{}, fmt.Errorf("%q isn't a group in this account", id)
}

// heldPermissions is what userID holds on vaultID, directly or through its groups.
func (f *FakeAccount) heldPermissions(vaultID, userID string) []string {
	held := slices.Clone(f.VaultUsers[vaultID][userID])
	for groupID, permissions := range f.VaultGroups[vaultID] {
		if slices.Contains(f.GroupMembers[groupID], userID) {
			held = append(held, permissions...)
		}
	}
	return held
}

func (f *FakeAccount) vault(id string) (Vault, error) {
	for _, v := range f.Vaults {
		if v.ID == id {
			return v, nil
		}
	}
	return Vault{}, fmt.Errorf("%q isn't a vault in this account", id)
}

func (f *FakeAccount) usersByID(ids []string) []User {
	users := []User{}
	for _, id := range ids {
		if u, err := f.user(id); err == nil {
			users = append(users, u)
		}
	}
	return users
}
