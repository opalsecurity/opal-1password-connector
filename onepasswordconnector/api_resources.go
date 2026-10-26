package onepasswordconnector

import (
	"errors"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"

	"github.com/opalsecurity/opal-1password-connector/internal/op"
)

// ResourcesAPI exposes 1Password vaults as resources, with one access level per vault permission.
type ResourcesAPI struct{ *Connector }

// GetResources - Get /resources
func (api *ResourcesAPI) GetResources(c *gin.Context) {
	response := ResourcesResponse{Resources: []Resource{}}
	if c.Query("parent_id") != "" {
		c.JSON(http.StatusOK, response)
		return
	}
	vaults, err := api.listVaults(c)
	if err != nil {
		writeError(c, err)
		return
	}
	for _, v := range vaults {
		v, err := api.withDescription(c, v)
		if err != nil {
			writeError(c, err)
			return
		}
		if v.Personal() {
			continue
		}
		response.Resources = append(response.Resources, toResource(v))
	}
	c.JSON(http.StatusOK, response)
}

// withDescription fills in the vault description and type, which `op vault list` omits, via `op vault get`.
func (api *ResourcesAPI) withDescription(c *gin.Context, vault op.Vault) (op.Vault, error) {
	if vault.Description != "" {
		return vault, nil
	}
	detail, err := api.op.GetVault(c, vault.ID)
	if errors.Is(err, op.ErrNotFound) {
		return vault, nil
	}
	return detail, err
}

// GetResource - Get /resources/:resource_id
func (api *ResourcesAPI) GetResource(c *gin.Context) {
	vault, err := api.op.GetVault(c, c.Param("resource_id"))
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, ResourceResponse{Resource: toResource(vault)})
}

// GetResourceAccessLevels - Get /resources/:resource_id/access_levels
func (api *ResourcesAPI) GetResourceAccessLevels(c *gin.Context) {
	permissions, err := api.permissions(c)
	if err != nil {
		writeError(c, err)
		return
	}
	response := ResourceAccessLevelsResponse{AccessLevels: []AccessLevel{}}
	for _, p := range permissions {
		response.AccessLevels = append(response.AccessLevels, accessLevel(p))
	}
	c.JSON(http.StatusOK, response)
}

// GetResourceUsers - Get /resources/:resource_id/users
//
// A user appears once per access-level bundle they hold: permissions another held permission requires
// are folded into it rather than reported separately.
func (api *ResourcesAPI) GetResourceUsers(c *gin.Context) {
	users, err := api.op.ListVaultUsers(c, c.Param("resource_id"))
	if err != nil {
		writeError(c, err)
		return
	}
	response := ResourceUsersResponse{Users: []ResourceUser{}}
	for _, u := range activeUsers(users) {
		held, err := api.heldPermissions(c, u.Permissions)
		if err != nil {
			writeError(c, err)
			return
		}
		for _, p := range op.TopPermissions(held) {
			response.Users = append(response.Users, ResourceUser{UserId: u.ID, Email: u.Email, AccessLevel: accessLevel(p)})
		}
	}
	c.JSON(http.StatusOK, response)
}

// AddResourceUser - Post /resources/:resource_id/users
func (api *ResourcesAPI) AddResourceUser(c *gin.Context) {
	request, valid := bind[AddResourceUserRequest](c)
	if !valid {
		return
	}
	err := api.guardSelf(c, request.UserId)
	var permission string
	if err == nil {
		permission, err = api.requestedPermission(c, request.AccessLevelId)
	}
	if err == nil {
		err = api.op.GrantVaultUser(c, c.Param("resource_id"), request.UserId, op.ExpandGrant(permission))
	}
	if err != nil {
		writeError(c, err)
		return
	}
	ok(c)
}

// RemoveResourceUser - Delete /resources/:resource_id/users/:user_id
//
// Revoking an access level revokes its bundle and everything that depends on it, except what the
// user's other bundles still require; with no access level, every directly held permission is
// revoked. Nothing left to revoke is success. A user whose access is inherited from a 1Password group
// gets 409, since only removing them from the group revokes it. The connector's own identity gets 403.
func (api *ResourcesAPI) RemoveResourceUser(c *gin.Context) {
	vaultID, userID := c.Param("resource_id"), c.Param("user_id")
	if err := api.guardSelf(c, userID); err != nil {
		writeError(c, err)
		return
	}
	users, err := api.op.ListVaultUsers(c, vaultID)
	if err != nil {
		writeError(c, err)
		return
	}
	userIndex := slices.IndexFunc(users, func(u op.User) bool { return u.ID == userID })
	if userIndex < 0 {
		ok(c)
		return
	}
	toRevoke := revocation(users[userIndex].Permissions, c.Query("access_level_id"))
	if len(toRevoke) == 0 {
		ok(c)
		return
	}
	if err := api.op.RevokeVaultUser(c, vaultID, userID, toRevoke); err != nil {
		writeError(c, err)
		return
	}
	ok(c)
}

// revocation returns which of held to revoke for accessLevelID ("" means all of them): the bundle
// (accessLevelID plus its dependencies) and its dependents, minus what the remaining bundles require.
func revocation(held []string, accessLevelID string) []string {
	if accessLevelID == "" {
		return held
	}
	candidates := append(op.ExpandGrant(accessLevelID), op.ExpandRevoke(accessLevelID)...)
	var keep []string
	for _, p := range held {
		if !slices.Contains(candidates, p) {
			keep = append(keep, op.ExpandGrant(p)...)
		}
	}
	return slices.DeleteFunc(intersect(held, candidates), func(p string) bool { return slices.Contains(keep, p) })
}
