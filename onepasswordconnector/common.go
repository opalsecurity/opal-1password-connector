package onepasswordconnector

import (
	"errors"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/opalsecurity/opal-1password-connector/internal/op"
)

// cacheTTL roughly spans one Opal sync cycle.
const cacheTTL = 60 * time.Second

// selfTTL caches the connector's own user ID; it only changes if the credentials do, which restarts it.
const selfTTL = 24 * time.Hour

// Connector serves Opal's custom connector API from a 1Password account.
type Connector struct {
	op  *op.Client
	now func() time.Time

	accountType    cached[string]
	self           cached[string]
	users          cached[[]op.User]
	groups         cached[[]op.Group]
	groupResources cached[map[string][]GroupResource]
}

func NewConnector(client *op.Client, now func() time.Time) *Connector {
	return &Connector{op: client, now: now}
}

// NewServer wires the signature check and every route onto a gin engine.
func NewServer(connector *Connector, signingSecret string) *gin.Engine {
	router := gin.New()
	// Handlers pass *gin.Context to op; this makes cancelling the request cancel the subprocess.
	router.ContextWithFallback = true
	router.Use(gin.LoggerWithConfig(gin.LoggerConfig{SkipPaths: []string{"/healthz", "/readyz"}}), gin.Recovery())
	// Registered before the signature check so load balancers and Kubernetes probes can reach them.
	router.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusOK) })
	// Ready only while this instance can sign in to 1Password, so a replica whose device still needs a
	// 2FA bootstrap gets no traffic. Not cached: it runs `op whoami`, which also keeps the session alive.
	// The error stays in the logs; this endpoint is unauthenticated.
	router.GET("/readyz", func(c *gin.Context) {
		if _, err := connector.op.Whoami(c); err != nil {
			log.Printf("readyz: %v", err)
			c.Status(http.StatusServiceUnavailable)
			return
		}
		c.Status(http.StatusOK)
	})
	router.Use(VerifySignature(signingSecret, connector.now))
	return NewRouterWithGinEngine(router, ApiHandleFunctions{
		EventsAPI:    EventsAPI{connector},
		GroupsAPI:    GroupsAPI{connector},
		ResourcesAPI: ResourcesAPI{connector},
		StatusAPI:    StatusAPI{connector},
		UsersAPI:     UsersAPI{connector},
	})
}

func (c *Connector) selfID(ctx *gin.Context) (string, error) {
	return c.self.get(c.now(), selfTTL, func() (string, error) { return c.op.Whoami(ctx) })
}

// listVaults lists the vaults the connector's identity can manage, including through its groups.
func (c *Connector) listVaults(ctx *gin.Context) ([]op.Vault, error) {
	self, err := c.selfID(ctx)
	if err != nil {
		return nil, err
	}
	return c.op.ListVaults(ctx, self)
}

func (c *Connector) permissions(ctx *gin.Context) ([]string, error) {
	accountType, err := c.accountType.get(c.now(), time.Hour, func() (string, error) {
		return c.op.AccountType(ctx)
	})
	return op.Permissions(accountType), err
}

func toGroup(g op.Group) Group {
	return Group{Id: g.ID, Name: g.Name, Description: g.Description}
}

func toResource(v op.Vault) Resource {
	return Resource{Id: v.ID, Name: v.Name, Description: v.Description}
}

// accessLevel names a permission's bundle: the permission plus everything granting it brings along.
func accessLevel(permission string) AccessLevel {
	name := permissionName(permission)
	var includes []string
	for _, dep := range op.ExpandGrant(permission) {
		if dep != permission {
			includes = append(includes, permissionName(dep))
		}
	}
	if len(includes) > 0 {
		name += " (+ " + strings.Join(includes, ", ") + ")"
	}
	return AccessLevel{Id: permission, Name: name}
}

func permissionName(permission string) string {
	name := strings.ReplaceAll(permission, "_", " ")
	return strings.ToUpper(name[:1]) + name[1:]
}

// intersect returns the elements of a that are also in b, in a's order.
func intersect(a, b []string) []string {
	return slices.DeleteFunc(slices.Clone(a), func(p string) bool { return !slices.Contains(b, p) })
}

// requestedPermission resolves Opal's access_level_id, defaulting to the account's base permission.
func (c *Connector) requestedPermission(ctx *gin.Context, accessLevelID string) (string, error) {
	permissions, err := c.permissions(ctx)
	if err != nil {
		return "", err
	}
	if accessLevelID == "" {
		return permissions[0], nil
	}
	if !slices.Contains(permissions, accessLevelID) {
		return "", errBadRequest{"unknown access level " + accessLevelID}
	}
	return accessLevelID, nil
}

// protectedGroups are the built-in groups the connector's identity needs to stay in for sync to work:
// they confer the account-wide and vault-management rights every write relies on.
var protectedGroups = []string{"Owners", "Administrators"}

// guardSelf refuses a write that would change the connector's own 1Password identity. Removing it
// from Owners/Administrators, or revoking its vault access, would break every later sync.
func (c *Connector) guardSelf(ctx *gin.Context, userID string) error {
	self, err := c.selfID(ctx)
	if err != nil {
		return err
	}
	if userID == self {
		return errForbidden{"refusing to change the connector's own 1Password identity " + userID}
	}
	return nil
}

// guardProtectedGroup refuses revoking vault access from Owners/Administrators: the connector reaches
// vaults through those groups, so the vault would drop out of sync.
func (c *Connector) guardProtectedGroup(ctx *gin.Context, groupID string) error {
	group, err := c.op.GetGroup(ctx, groupID)
	if err != nil {
		return err
	}
	if slices.Contains(protectedGroups, group.Name) {
		return errForbidden{"refusing to revoke vault access from the built-in " + group.Name + " group"}
	}
	return nil
}

// heldPermissions filters held down to the permissions this account tier exposes.
func (c *Connector) heldPermissions(ctx *gin.Context, held []string) ([]string, error) {
	permissions, err := c.permissions(ctx)
	if err != nil {
		return nil, err
	}
	return intersect(held, permissions), nil
}

// bind parses the JSON request body, answering 400 itself when it is malformed.
func bind[T any](c *gin.Context) (T, bool) {
	var request T
	if err := c.ShouldBindJSON(&request); err != nil {
		writeError(c, errBadRequest{err.Error()})
		return request, false
	}
	return request, true
}

type errBadRequest struct{ message string }

func (e errBadRequest) Error() string { return e.message }

type errForbidden struct{ message string }

func (e errForbidden) Error() string { return e.message }

var errorStatuses = []struct {
	kind   error
	status int
}{
	{op.ErrNotFound, http.StatusNotFound},
	{op.ErrNoDirectAccess, http.StatusConflict},
	{op.ErrRateLimited, http.StatusTooManyRequests},
	{op.ErrAuth, http.StatusBadGateway},
	{op.ErrTwoFactor, http.StatusBadGateway},
	{op.ErrBootstrap, http.StatusBadGateway},
}

func writeError(c *gin.Context, err error) {
	status := http.StatusInternalServerError
	var badRequest errBadRequest
	var forbidden errForbidden
	switch {
	case errors.As(err, &badRequest):
		status = http.StatusBadRequest
	case errors.As(err, &forbidden):
		status = http.StatusForbidden
	}
	for _, e := range errorStatuses {
		if errors.Is(err, e.kind) {
			status = e.status
			break
		}
	}
	log.Printf("%s %s: %d %v", c.Request.Method, c.FullPath(), status, err)
	c.AbortWithStatusJSON(status, Error{Code: int32(status), Message: err.Error()})
}

func ok(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{})
}

type cached[T any] struct {
	mu    sync.Mutex
	at    time.Time
	value T
	valid bool
}

func (c *cached[T]) get(now time.Time, ttl time.Duration, fetch func() (T, error)) (T, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.valid && now.Sub(c.at) < ttl {
		return c.value, nil
	}
	value, err := fetch()
	if err != nil {
		return value, err
	}
	c.value, c.at, c.valid = value, now, true
	return value, nil
}

func (c *cached[T]) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.valid = false
}
