package onepasswordconnector

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Version is the connector build, stamped by the release image with -ldflags. GET /status reports it
// with the implementation name, so Opal can show which connector build each app runs.
var Version = "dev"

const implementation = "opal-1password-connector"

type StatusAPI struct{ *Connector }

// GetStatus - Get /status
//
// Uses `op account get` rather than `op whoami`: under the desktop app integration, whoami reports
// "not signed in" instead of prompting to unlock.
func (api *StatusAPI) GetStatus(c *gin.Context) {
	if _, err := api.op.AccountType(c); err != nil {
		writeError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"implementation": implementation, "version": Version})
}
