package onepasswordconnector

import (
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"

	"github.com/opalsecurity/opal-1password-connector/internal/op"
)

// GroupsAPI exposes 1Password groups, their members, and their vault access. 1Password has no
// nested groups.
type GroupsAPI struct{ *Connector }

// GetGroups - Get /groups
func (api *GroupsAPI) GetGroups(c *gin.Context) {
	groups, err := api.listGroups(c)
	if err != nil {
		writeError(c, err)
		return
	}
	response := GroupsResponse{Groups: []Group{}}
	for _, g := range groups {
		if g.Active() {
			response.Groups = append(response.Groups, toGroup(g))
		}
	}
	c.JSON(http.StatusOK, response)
}

// GetGroup - Get /groups/:group_id
func (api *GroupsAPI) GetGroup(c *gin.Context) {
	group, err := api.op.GetGroup(c, c.Param("group_id"))
	if err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, GroupResponse{Group: toGroup(group)})
}

// GetGroupUsers - Get /groups/:group_id/users
func (api *GroupsAPI) GetGroupUsers(c *gin.Context) {
	users, err := api.op.ListGroupUsers(c, c.Param("group_id"))
	if err != nil {
		writeError(c, err)
		return
	}
	response := GroupUsersResponse{Users: []GroupUser{}}
	for _, u := range activeUsers(users) {
		response.Users = append(response.Users, GroupUser{UserId: u.ID, Email: u.Email})
	}
	c.JSON(http.StatusOK, response)
}

// AddGroupUser - Post /groups/:group_id/users
func (api *GroupsAPI) AddGroupUser(c *gin.Context) {
	request, valid := bind[AddGroupUserRequest](c)
	if !valid {
		return
	}
	err := api.guardSelf(c, request.UserId)
	if err == nil {
		err = api.op.GrantGroupUser(c, c.Param("group_id"), request.UserId)
	}
	if err != nil {
		writeError(c, err)
		return
	}
	ok(c)
}

// RemoveGroupUser - Delete /groups/:group_id/users/:user_id
//
// The connector's own identity is refused (403): removing it from Owners/Administrators breaks sync.
func (api *GroupsAPI) RemoveGroupUser(c *gin.Context) {
	userID := c.Param("user_id")
	err := api.guardSelf(c, userID)
	if err == nil {
		err = api.op.RevokeGroupUser(c, c.Param("group_id"), userID)
	}
	if err != nil {
		writeError(c, err)
		return
	}
	ok(c)
}

// GetGroupResources - Get /groups/:group_id/resources
//
// Opal stores one access level per group grant, so each vault reports the group's primary permission.
func (api *GroupsAPI) GetGroupResources(c *gin.Context) {
	byGroup, err := api.groupResources.get(api.now(), cacheTTL, func() (map[string][]GroupResource, error) {
		return api.loadGroupResources(c)
	})
	if err != nil {
		writeError(c, err)
		return
	}
	resources := byGroup[c.Param("group_id")]
	if resources == nil {
		resources = []GroupResource{}
	}
	c.JSON(http.StatusOK, GroupResourcesResponse{Resources: resources})
}

// AddGroupResource - Post /groups/:group_id/resources
func (api *GroupsAPI) AddGroupResource(c *gin.Context) {
	request, valid := bind[AddGroupResourceRequest](c)
	if !valid {
		return
	}
	permission, err := api.requestedPermission(c, request.AccessLevelId)
	if err == nil {
		err = api.op.GrantVaultGroup(c, request.ResourceId, c.Param("group_id"), op.ExpandGrant(permission))
	}
	if err != nil {
		writeError(c, err)
		return
	}
	api.groupResources.reset()
	ok(c)
}

// RemoveGroupResource - Delete /groups/:group_id/resources/:resource_id
//
// Owners/Administrators are refused (403): the connector manages vaults through them.
func (api *GroupsAPI) RemoveGroupResource(c *gin.Context) {
	vaultID, groupID := c.Param("resource_id"), c.Param("group_id")
	if err := api.guardProtectedGroup(c, groupID); err != nil {
		writeError(c, err)
		return
	}
	groups, err := api.op.ListVaultGroups(c, vaultID)
	if err != nil {
		writeError(c, err)
		return
	}
	groupIndex := slices.IndexFunc(groups, func(g op.Group) bool { return g.ID == groupID })
	if groupIndex < 0 {
		ok(c)
		return
	}
	toRevoke := revocation(groups[groupIndex].Permissions, c.Query("access_level_id"))
	if len(toRevoke) == 0 {
		ok(c)
		return
	}
	if err := api.op.RevokeVaultGroup(c, vaultID, groupID, toRevoke); err != nil {
		writeError(c, err)
		return
	}
	api.groupResources.reset()
	ok(c)
}

// GetGroupMemberGroups - Get /groups/:group_id/member-groups
func (api *GroupsAPI) GetGroupMemberGroups(c *gin.Context) {
	c.JSON(http.StatusOK, GroupMemberGroupsResponse{Groups: []GroupMemberGroup{}})
}

// AddGroupMemberGroup - Post /groups/:group_id/member-groups
func (api *GroupsAPI) AddGroupMemberGroup(c *gin.Context) { DefaultHandleFunc(c) }

// RemoveGroupMemberGroup - Delete /groups/:group_id/member-groups/:member_group_id
func (api *GroupsAPI) RemoveGroupMemberGroup(c *gin.Context) { DefaultHandleFunc(c) }

func (api *GroupsAPI) listGroups(c *gin.Context) ([]op.Group, error) {
	return api.groups.get(api.now(), cacheTTL, func() ([]op.Group, error) { return api.op.ListGroups(c) })
}

// loadGroupResources fans out one `op vault group list` per vault; `op` has no per-group lookup.
func (api *GroupsAPI) loadGroupResources(c *gin.Context) (map[string][]GroupResource, error) {
	vaults, err := api.listVaults(c)
	if err != nil {
		return nil, err
	}
	byGroup := map[string][]GroupResource{}
	for _, v := range vaults {
		groups, err := api.op.ListVaultGroups(c, v.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range groups {
			held, err := api.heldPermissions(c, g.Permissions)
			if err != nil {
				return nil, err
			}
			if primary := op.PrimaryPermission(held); primary != "" {
				byGroup[g.ID] = append(byGroup[g.ID], GroupResource{ResourceId: v.ID, AccessLevel: accessLevel(primary)})
			}
		}
	}
	return byGroup, nil
}
