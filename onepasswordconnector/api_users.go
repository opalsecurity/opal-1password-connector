package onepasswordconnector

import (
	"log"
	"net/http"
	"net/mail"

	"github.com/gin-gonic/gin"

	"github.com/opalsecurity/opal-1password-connector/internal/op"
)

// UsersAPI lists 1Password users. User provisioning is out of scope.
type UsersAPI struct{ *Connector }

// GetUsers - Get /users
func (api *UsersAPI) GetUsers(c *gin.Context) {
	users, err := api.users.get(api.now(), cacheTTL, func() ([]op.User, error) { return api.op.ListUsers(c) })
	if err != nil {
		writeError(c, err)
		return
	}
	response := UsersResponse{Users: []User{}}
	for _, u := range activeUsers(users) {
		response.Users = append(response.Users, User{Id: u.ID, Email: u.Email})
	}
	c.JSON(http.StatusOK, response)
}

// CreateUser - Post /users
func (api *UsersAPI) CreateUser(c *gin.Context) { DefaultHandleFunc(c) }

// DeleteUser - Delete /users/:user_id
func (api *UsersAPI) DeleteUser(c *gin.Context) { DefaultHandleFunc(c) }

// activeUsers drops suspended/invited users and users whose email Opal could not match.
func activeUsers(users []op.User) []op.User {
	var active []op.User
	for _, u := range users {
		if !u.Active() {
			continue
		}
		if _, err := mail.ParseAddress(u.Email); err != nil {
			log.Printf("skipping 1Password user %s: invalid email", u.ID)
			continue
		}
		active = append(active, u)
	}
	return active
}
