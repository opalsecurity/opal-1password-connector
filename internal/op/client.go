package op

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

// runTimeout caps one logical `op` call (including a re-auth retry) so a hung CLI cannot hold the
// session and cache locks forever.
const runTimeout = 60 * time.Second

type User struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Email       string   `json:"email"`
	State       string   `json:"state"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// isActive treats a missing state as active; 1Password only reports SUSPENDED/INVITED explicitly.
func isActive(state string) bool { return state == "" || state == "ACTIVE" }

func (u User) Active() bool  { return isActive(u.State) }
func (g Group) Active() bool { return isActive(g.State) }

type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	State       string   `json:"state"`
	Permissions []string `json:"permissions"`
}

type Vault struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// Type is only reported by `op vault get`, e.g. PERSONAL for a user's own private vault.
	Type string `json:"type"`
}

// Personal reports a user's own private vault, which can't be shared.
func (v Vault) Personal() bool { return v.Type == "PERSONAL" }

// Client runs typed `op` commands. With a Session it authenticates via `--session`; without one it
// relies on the 1Password desktop app integration (local development only).
type Client struct {
	exec    Exec
	session *Session
	account string
}

func NewClient(exec Exec, session *Session, account string) *Client {
	return &Client{exec: exec, session: session, account: account}
}

func (c *Client) AccountType(ctx context.Context) (string, error) {
	var account struct {
		Type string `json:"type"`
	}
	err := c.run(ctx, &account, "account", "get")
	return account.Type, err
}

// Whoami returns the user ID the connector is signed in as.
func (c *Client) Whoami(ctx context.Context) (string, error) {
	var whoami struct {
		UserUUID string `json:"user_uuid"`
	}
	err := c.run(ctx, &whoami, "whoami")
	if err == nil && whoami.UserUUID == "" {
		err = errors.New("op whoami returned no user_uuid")
	}
	return whoami.UserUUID, err
}

func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	return get[[]User](ctx, c, "user", "list")
}

func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	return get[[]Group](ctx, c, "group", "list")
}

func (c *Client) GetGroup(ctx context.Context, groupID string) (Group, error) {
	return get[Group](ctx, c, "group", "get", groupID)
}

func (c *Client) ListGroupUsers(ctx context.Context, groupID string) ([]User, error) {
	return get[[]User](ctx, c, "group", "user", "list", groupID)
}

// ListVaults lists the vaults userID can access directly or through a group. Plain `op vault list`
// would only list vaults userID can view items in, missing the ones Owners/Administrators hold only
// manage_vault on: every shared vault, by default.
func (c *Client) ListVaults(ctx context.Context, userID string) ([]Vault, error) {
	return get[[]Vault](ctx, c, "vault", "list", "--user", userID)
}

func (c *Client) GetVault(ctx context.Context, vaultID string) (Vault, error) {
	return get[Vault](ctx, c, "vault", "get", vaultID)
}

func (c *Client) ListVaultUsers(ctx context.Context, vaultID string) ([]User, error) {
	return get[[]User](ctx, c, "vault", "user", "list", vaultID)
}

func (c *Client) ListVaultGroups(ctx context.Context, vaultID string) ([]Group, error) {
	return get[[]Group](ctx, c, "vault", "group", "list", vaultID)
}

func (c *Client) GrantVaultUser(
	ctx context.Context,
	vaultID, userID string,
	permissions []string,
) error {
	return c.vaultWrite(ctx, "user", "grant", vaultID, userID, permissions)
}

func (c *Client) RevokeVaultUser(
	ctx context.Context,
	vaultID, userID string,
	permissions []string,
) error {
	return c.vaultWrite(ctx, "user", "revoke", vaultID, userID, permissions)
}

func (c *Client) GrantVaultGroup(
	ctx context.Context,
	vaultID, groupID string,
	permissions []string,
) error {
	return c.vaultWrite(ctx, "group", "grant", vaultID, groupID, permissions)
}

func (c *Client) RevokeVaultGroup(
	ctx context.Context,
	vaultID, groupID string,
	permissions []string,
) error {
	return c.vaultWrite(ctx, "group", "revoke", vaultID, groupID, permissions)
}

// GrantGroupUser adds userID to groupID as a member. Already being a member is success.
func (c *Client) GrantGroupUser(ctx context.Context, groupID, userID string) error {
	err := c.write(ctx, "group", "user", "grant", "--group", groupID, "--user", userID, "--role", "member")
	if errors.Is(err, ErrAlreadyMember) {
		return nil
	}
	return err
}

// RevokeGroupUser removes userID from groupID. Not being a member is success.
func (c *Client) RevokeGroupUser(ctx context.Context, groupID, userID string) error {
	err := c.write(ctx, "group", "user", "revoke", "--group", groupID, "--user", userID)
	if errors.Is(err, ErrNotMember) {
		return nil
	}
	return err
}

// vaultWrite passes dependent permissions explicitly with --no-input; otherwise `op` blocks on a
// confirmation prompt.
func (c *Client) vaultWrite(
	ctx context.Context,
	principal, action, vaultID, principalID string,
	permissions []string,
) error {
	return c.write(ctx,
		"vault", principal, action,
		"--vault", vaultID,
		"--"+principal, principalID,
		"--permissions", strings.Join(permissions, ","),
		"--no-input",
	)
}

// write runs a mutating command detached from the caller's cancellation. A client disconnect or a
// proxy timeout must not kill `op` partway through a grant or revoke: 1Password would be left
// changed with nothing recording what landed. runTimeout still bounds it.
func (c *Client) write(ctx context.Context, args ...string) error {
	return c.run(context.WithoutCancel(ctx), nil, args...)
}

// get runs one command and decodes its JSON output into a T.
func get[T any](ctx context.Context, c *Client, args ...string) (T, error) {
	var out T
	return out, c.run(ctx, &out, args...)
}

// run executes one command, re-authenticating and retrying once if the session was rejected.
func (c *Client) run(ctx context.Context, out any, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()
	token, err := c.runOnce(ctx, out, args)
	if errors.Is(err, ErrAuth) && c.session != nil {
		c.session.Invalidate(token)
		_, err = c.runOnce(ctx, out, args)
	}
	return err
}

// runOnce returns the session token it used so a failed one can be invalidated precisely.
func (c *Client) runOnce(ctx context.Context, out any, args []string) (string, error) {
	args = append(slices.Clone(args), "--format=json")
	var token string
	if c.session != nil {
		var err error
		token, err = c.session.Token(ctx)
		if err != nil {
			return "", err
		}
		args = append(args, "--session", token)
	} else if c.account != "" {
		args = append(args, "--account", c.account)
	}
	stdout, err := c.exec(ctx, args, nil, "")
	if err != nil || out == nil {
		return token, err
	}
	return token, json.Unmarshal(stdout, out)
}
